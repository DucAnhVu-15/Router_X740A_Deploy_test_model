#include "hostname_engine.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cmath>
#include <cstring>
#include <map>
#include <stdexcept>

namespace sdc {
namespace {

const char *const kUnknown = "__unknown__";
constexpr size_t kMake = 0, kType = 1, kModel = 2;
constexpr size_t kMaxChars = 255;  // tính cả hai dấu cách đệm

class Reader {
public:
    Reader(const uint8_t *data, size_t size) : p_(data), end_(data + size) {}

    const uint8_t *take(size_t bytes) {
        if (static_cast<size_t>(end_ - p_) < bytes) throw std::runtime_error("sdc_hn.bin bị cụt");
        const uint8_t *at = p_;
        p_ += bytes;
        return at;
    }
    uint32_t u32() {
        uint32_t value;
        std::memcpy(&value, take(4), 4);
        return value;
    }
    float f32() {
        float value;
        std::memcpy(&value, take(4), 4);
        return value;
    }
    std::string string() {
        uint32_t size = u32();
        const uint8_t *at = take(size);
        return std::string(reinterpret_cast<const char *>(at), size);
    }
    std::vector<std::string> strings() {
        uint32_t count = u32();
        std::vector<std::string> values;
        values.reserve(count);
        for (uint32_t i = 0; i < count; ++i) values.push_back(string());
        return values;
    }
    // Mảng nằm sát nhau trong file, căn lại trước khi đọc kiểu rộng.
    template <typename T>
    std::vector<T> copy_array(size_t &count) {
        count = u32();
        std::vector<T> values(count);
        std::memcpy(values.data(), take(count * sizeof(T)), count * sizeof(T));
        return values;
    }
    template <typename T>
    const T *view(size_t &count) {
        count = u32();
        return reinterpret_cast<const T *>(take(count * sizeof(T)));
    }

private:
    const uint8_t *p_, *end_;
};

// Mảng số cần căn lề: giữ một bản sao sống cùng tiến trình.
template <typename T>
const T *keep(std::vector<T> &&values) {
    static std::vector<std::vector<uint8_t>> store;
    std::vector<uint8_t> bytes(values.size() * sizeof(T) + alignof(std::max_align_t));
    store.push_back(std::move(bytes));
    auto &slot = store.back();
    void *at = slot.data();
    size_t space = slot.size();
    at = std::align(alignof(T), values.size() * sizeof(T), at, space);
    std::memcpy(at, values.data(), values.size() * sizeof(T));
    return static_cast<const T *>(at);
}

std::unique_ptr<re2::RE2> compile(const std::string &pattern) {
    auto regex = std::make_unique<re2::RE2>(pattern, re2::RE2::Quiet);
    if (!regex->ok()) throw std::runtime_error("regex lỗi: " + regex->error());
    return regex;
}

// Giải mã UTF-8 chặt. Trả false nếu chuỗi không hợp lệ.
bool decode_utf8(const std::string &text, std::vector<uint32_t> &codes) {
    const auto *s = reinterpret_cast<const uint8_t *>(text.data());
    size_t i = 0, n = text.size();
    while (i < n) {
        uint8_t c = s[i];
        uint32_t cp;
        size_t extra;
        if (c < 0x80) {
            cp = c;
            extra = 0;
        } else if ((c >> 5) == 0x6) {
            cp = c & 0x1F;
            extra = 1;
        } else if ((c >> 4) == 0xE) {
            cp = c & 0x0F;
            extra = 2;
        } else if ((c >> 3) == 0x1E) {
            cp = c & 0x07;
            extra = 3;
        } else {
            return false;
        }
        if (extra > 0 && i + extra >= n) return false;
        for (size_t k = 1; k <= extra; ++k) {
            if ((s[i + k] & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (s[i + k] & 0x3F);
        }
        codes.push_back(cp);
        i += extra + 1;
    }
    return true;
}

}  // namespace

HostnameEngine::~HostnameEngine() {
    if (map_) munmap(map_, map_size_);
}

size_t HostnameEngine::rule_count() const {
    return rules_[0].size() + rules_[1].size() + rules_[2].size() + evidence_.size() + 1;
}

void HostnameEngine::load(const std::string &path) {
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) throw std::runtime_error("không mở được " + path);
    struct stat st {};
    fstat(fd, &st);
    map_size_ = static_cast<size_t>(st.st_size);
    map_ = mmap(nullptr, map_size_, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (map_ == MAP_FAILED) {
        map_ = nullptr;
        throw std::runtime_error("mmap thất bại");
    }

    Reader in(static_cast<const uint8_t *>(map_), map_size_);
    if (std::memcmp(in.take(8), "SDCHN1\0\0", 8) != 0) throw std::runtime_error("sai định dạng sdc_hn.bin");
    in.string();  // run_id
    bad_ = compile(in.string());

    size_t count = 0;
    auto alias = in.copy_array<uint32_t>(count);
    alias_.resize(count / 2);
    for (size_t i = 0; i < alias_.size(); ++i) alias_[i] = {alias[2 * i], alias[2 * i + 1]};
    base_ = in.u32();

    gram_keys_ = keep(in.copy_array<uint64_t>(gram_count_));
    size_t values = 0;
    gram_values_ = keep(in.copy_array<uint32_t>(values));
    idf_ = keep(in.copy_array<float>(features_));

    for (auto &item : experts_) {
        item.labels = in.strings();
        item.classes = in.u32();
        item.threshold = in.f32();
        size_t n = 0;
        item.scale = keep(in.copy_array<float>(n));
        item.bias = keep(in.copy_array<float>(n));
        item.weight = in.view<int8_t>(n);  // int8 không cần căn lề, đọc thẳng từ file
    }

    for (auto &rules : rules_) {
        uint32_t n = in.u32();
        rules.reserve(n);
        for (uint32_t i = 0; i < n; ++i) {
            std::string pattern = in.string();
            std::string label = in.string();
            rules.push_back({compile(pattern), std::move(label)});
        }
    }

    uint32_t evidence = in.u32();
    for (uint32_t i = 0; i < evidence; ++i) {
        std::string label = in.string();
        evidence_[label] = compile(in.string());
    }

    for (auto &v : in.strings()) strong_mdns_.insert(std::move(v));
    for (auto &v : in.strings()) strong_oui_.insert(std::move(v));

    for (size_t h = 0; h < 3; ++h) {
        labels_[h] = in.strings();
        for (size_t i = 0; i < labels_[h].size(); ++i) label_index_[h][labels_[h][i]] = static_cast<int>(i);
    }

    size_t n = 0;
    type_guard_ = in.view<uint8_t>(n);
    mask_make_ = in.view<uint8_t>(n);
    mask_type_ = in.view<uint8_t>(n);
    implied_make_ = keep(in.copy_array<uint16_t>(n));
    implied_type_ = keep(in.copy_array<uint16_t>(n));

    uint32_t pairs = in.u32();
    for (uint32_t i = 0; i < pairs; ++i) {
        std::string coarse = in.string();
        std::string fine = in.string();
        type_refine_.emplace_back(std::move(coarse), std::move(fine));
    }
}

// LabelEncoder trong graph trả 0 cho nhãn lạ, giữ nguyên hành vi đó.
int HostnameEngine::label_index(size_t head, const std::string &label) const {
    auto found = label_index_[head].find(label);
    return found == label_index_[head].end() ? 0 : found->second;
}

bool HostnameEngine::encode(const std::string &hostname, std::vector<std::pair<uint32_t, float>> &x,
                            size_t &length) const {
    std::vector<uint32_t> codes;
    codes.reserve(hostname.size() + 2);
    codes.push_back(' ');
    if (!decode_utf8(hostname, codes)) return false;
    codes.push_back(' ');
    length = codes.size();

    std::vector<uint32_t> ids(codes.size());
    for (size_t i = 0; i < codes.size(); ++i) {
        auto it = std::lower_bound(alias_.begin(), alias_.end(), std::make_pair(codes[i], uint32_t{0}));
        ids[i] = (it != alias_.end() && it->first == codes[i]) ? it->second : 0;
    }

    std::map<uint32_t, uint32_t> counts;
    for (size_t n = 3; n <= 5; ++n) {
        uint64_t power = 1;
        for (size_t k = 0; k < n; ++k) power *= base_;
        for (size_t i = 0; i + n <= ids.size(); ++i) {
            uint64_t key = 0;
            bool known = true;
            for (size_t k = 0; k < n; ++k) {
                known = known && ids[i + k] != 0;  // ký tự lạ không thuộc n-gram nào
                key = key * base_ + ids[i + k];
            }
            if (!known) continue;
            key += power;
            const uint64_t *hit = std::lower_bound(gram_keys_, gram_keys_ + gram_count_, key);
            if (hit != gram_keys_ + gram_count_ && *hit == key) ++counts[gram_values_[hit - gram_keys_]];
        }
    }

    x.clear();
    double squared = 0;
    for (const auto &[feature, count] : counts) {
        float tf = std::log(static_cast<float>(count)) + 1.0f;
        float weighted = tf * idf_[feature];
        squared += static_cast<double>(weighted) * weighted;
        x.emplace_back(feature, weighted);
    }
    float norm = static_cast<float>(std::sqrt(squared));
    float safe = std::max(norm, 1e-12f);
    for (auto &entry : x) entry.second /= safe;
    return norm > 0;
}

HostnameEngine::Candidate HostnameEngine::expert(size_t head,
                                                 const std::vector<std::pair<uint32_t, float>> &x,
                                                 bool valid, const std::string &hostname) const {
    const Expert &item = experts_[head];
    std::vector<double> score(item.classes, 0.0);
    for (const auto &[feature, value] : x) {
        const int8_t *row = item.weight + feature * item.classes;
        for (size_t c = 0; c < item.classes; ++c)
            score[c] += static_cast<double>(value) * (static_cast<float>(row[c]) * item.scale[c]);
    }

    double total = 0;
    size_t best = 0;
    double best_value = -1;
    for (size_t c = 0; c < item.classes; ++c) {
        float linear = static_cast<float>(score[c]) + item.bias[c];
        double sigmoid = 1.0 / (1.0 + std::exp(-static_cast<double>(linear)));
        total += sigmoid;
        if (sigmoid > best_value) {
            best_value = sigmoid;
            best = c;
        }
    }

    Candidate out;
    out.label = item.labels[best];
    float confidence = static_cast<float>(best_value / total);
    out.accepted = valid && confidence >= item.threshold;
    if (out.accepted && head == kMake) {
        auto found = evidence_.find(out.label);
        out.accepted = found != evidence_.end() && re2::RE2::FullMatch(hostname, *found->second);
    }
    return out;
}

Labels HostnameEngine::run(const std::string &hostname, const std::string &mdns_model,
                           const std::string &mac_oui, const Labels &packet) const {
    // Tương đương nhánh else của If: không có hostname thì giữ nguyên kết quả packet.
    if (re2::RE2::FullMatch(hostname, *bad_)) return packet;

    std::vector<std::pair<uint32_t, float>> x;
    size_t length = 0;
    bool usable = encode(hostname, x, length);
    if (length == 0) return packet;  // UTF-8 hỏng: bản graph báo lỗi, ở đây coi như không có hostname
    const bool short_enough = length <= kMaxChars;
    const bool valid = usable && short_enough;

    Labels host;
    std::array<bool, 3> rule_hit{false, false, false};
    for (size_t h = 0; h < 3; ++h) {
        Candidate candidate = expert(h, x, valid, hostname);
        host[h] = candidate.accepted ? candidate.label : kUnknown;
        if (!short_enough) continue;
        for (const Rule &rule : rules_[h]) {  // luật đầu tiên khớp thì thắng
            if (re2::RE2::FullMatch(hostname, *rule.regex)) {
                host[h] = rule.label;
                rule_hit[h] = true;
                break;
            }
        }
    }

    const size_t make_labels = labels_[kMake].size();
    const size_t type_labels = labels_[kType].size();
    auto allowed = [](const uint8_t *mask, size_t row, size_t column, size_t columns) {
        return mask[row * columns + column] != 0;
    };

    {   // guard_model_type: model từ hostname phải hợp với type packet đã biết
        int row = label_index(kModel, host[kModel]);
        bool ok = allowed(type_guard_, row, label_index(kType, packet[kType]), type_labels);
        if (!ok && packet[kType] != kUnknown && !rule_hit[kModel]) host[kModel] = kUnknown;
    }
    {   // guard_model_make: model phải hợp với cả make packet lẫn make hostname
        int row = label_index(kModel, host[kModel]);
        bool ok = allowed(mask_make_, row, label_index(kMake, packet[kMake]), make_labels) &&
                  allowed(mask_make_, row, label_index(kMake, host[kMake]), make_labels);
        if (!ok && !rule_hit[kModel]) host[kModel] = kUnknown;
    }

    const bool mdns_hit = strong_mdns_.count(mdns_model) > 0;
    const bool oui_hit = strong_oui_.count(mac_oui) > 0;
    Labels merged;
    std::array<bool, 3> taken{};
    for (size_t h = 0; h < 3; ++h) {
        bool strong = mdns_hit || (h == kMake && oui_hit) || !rule_hit[h];
        bool keep_base = strong && packet[h] != kUnknown;
        taken[h] = host[h] != kUnknown && !keep_base;
        merged[h] = taken[h] ? host[h] : packet[h];
    }

    {   // model_implies: model lấy từ hostname điền make/type còn thiếu
        int row = label_index(kModel, merged[kModel]);
        const std::string &make = labels_[kMake][implied_make_[row]];
        if (taken[kModel] && merged[kMake] == kUnknown && make != kUnknown) merged[kMake] = make;

        const std::string &kind = labels_[kType][implied_type_[row]];
        bool refinable = merged[kType] == kUnknown;
        for (const auto &[coarse, fine] : type_refine_)
            refinable = refinable || (merged[kType] == coarse && kind == fine);
        if (taken[kModel] && kind != kUnknown && refinable) merged[kType] = kind;
    }

    int driver = label_index(kModel, merged[kModel]);
    if (!allowed(mask_make_, driver, label_index(kMake, merged[kMake]), make_labels)) merged[kMake] = kUnknown;
    if (!allowed(mask_type_, driver, label_index(kType, merged[kType]), type_labels)) merged[kType] = kUnknown;
    return merged;
}

}  // namespace sdc
