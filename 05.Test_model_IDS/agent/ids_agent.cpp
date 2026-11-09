// IDS theo host: đọc pcap từ stdin (tcpdump -U -w -), cắt cửa sổ 50 gói hoặc 10 s, tính 97 đặc trưng,
// chạy model và in cảnh báo JSON mỗi dòng. Đặc trưng theo feature_pipeline_bruteforce_recon_dos.md.
// Ngữ cảnh 60/300 s tính theo khối 1 giây để không phải giữ từng gói, nên lệch tối đa 1 s ở mép khoảng.
//
// Cách dùng: tcpdump -i br-lan -n -U -s 128 -w - 'ip or arp' | ids_agent ids_model.ort [tuỳ chọn]
#include <fcntl.h>
#include <onnxruntime_cxx_api.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cmath>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <deque>
#include <fstream>
#include <iostream>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace {

constexpr size_t kPackets = 50;          // N_PKT
constexpr double kMaxSeconds = 10.0;     // T_MAX
constexpr double kNewGap = 300.0;        // NEW_GAP
constexpr double kShort = 60.0, kLong = 300.0;
constexpr double kEpisodeGap = 60.0;
constexpr double kDefaultThreshold = 0.8821289696466122;  // run 20261105_1550
constexpr size_t kFeatures = 97, kClasses = 4, kKinds = 12;
constexpr size_t kMaxFrame = 262144;
constexpr size_t kMaxItems = 70000;      // hơn 65.536 port và mọi ngưỡng đếm của model (cao nhất 17.284)
constexpr size_t kMaxQueue = 300000;
constexpr int kPollMilliseconds = 1000;
constexpr int kStatsSeconds = 30;
constexpr uint32_t kMagicMicro = 0xa1b2c3d4, kMagicNano = 0xa1b23c4d;
constexpr uint32_t kLinkEthernet = 1;

const char *const kKindNames[kKinds] = {"tcp", "syn", "synack", "rst", "fin_only", "null",
                                        "xmas", "ack_only", "udp", "icmp_echo", "arp_req", "arp_rep"};
enum Kind { kTcp, kSyn, kSynAck, kRst, kFinOnly, kNull, kXmas, kAckOnly, kUdp, kIcmpEcho, kArpReq, kArpRep };
constexpr uint16_t bit(Kind kind) { return static_cast<uint16_t>(1u << kind); }
constexpr uint16_t kIcmpUnreach = 1u << 12;  // chỉ dùng ở chiều nhận

const char *const kClassNames[3] = {"recon", "bruteforce", "dos"};

uint32_t swap32(uint32_t v) { return (v >> 24) | ((v >> 8) & 0xFF00) | ((v << 8) & 0xFF0000) | (v << 24); }
uint16_t read16(const uint8_t *p) { return static_cast<uint16_t>(p[0] << 8 | p[1]); }
uint32_t read32(const uint8_t *p) {
    return static_cast<uint32_t>(p[0]) << 24 | static_cast<uint32_t>(p[1]) << 16 | static_cast<uint32_t>(p[2]) << 8 | p[3];
}

std::string ip_text(uint32_t ip) {
    char text[16];
    std::snprintf(text, sizeof text, "%u.%u.%u.%u", ip >> 24, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255);
    return text;
}

uint32_t parse_ip(const std::string &text) {
    unsigned a = 0, b = 0, c = 0, d = 0;
    if (std::sscanf(text.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) < 3 || a > 255 || b > 255 || c > 255 || d > 255)
        throw std::runtime_error("IP sai: " + text);
    return a << 24 | b << 16 | c << 8 | d;
}

constexpr int kTimezoneOffset = 7 * 3600;  // giờ Việt Nam = UTC+7

std::string iso_time(double seconds) {
    std::time_t value = static_cast<std::time_t>(seconds) + kTimezoneOffset;
    std::tm parts{};
    gmtime_r(&value, &parts);
    char text[40];
    std::strftime(text, sizeof text, "%Y-%m-%dT%H:%M:%S+07:00", &parts);
    return text;
}

// Chỉ HH:MM:SS theo giờ VN, cho dòng log gọn.
std::string hms(double seconds) {
    std::time_t value = static_cast<std::time_t>(seconds) + kTimezoneOffset;
    std::tm parts{};
    gmtime_r(&value, &parts);
    char text[16];
    std::strftime(text, sizeof text, "%H:%M:%S", &parts);
    return text;
}

// Số nguyên có dấu phẩy ngăn nghìn, dễ đọc (vd 955814 -> 955,814).
std::string commas(uint64_t value) {
    std::string digits = std::to_string(value);
    std::string out;
    int count = 0;
    for (auto it = digits.rbegin(); it != digits.rend(); ++it) {
        if (count && count % 3 == 0) out.push_back(',');
        out.push_back(*it);
        ++count;
    }
    std::reverse(out.begin(), out.end());
    return out;
}

std::string upper(const char *text) {
    std::string out(text);
    for (char &c : out) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return out;
}

struct Packet {
    double ts = 0;
    uint32_t length = 0, src = 0, dst = 0;
    int32_t dport = -1;
    uint16_t kinds = 0;
};

// Trả về false nếu gói không có IPv4 hoặc ARP (IPv6, LLDP...), những gói này không vào đặc trưng.
bool parse_frame(const uint8_t *data, size_t size, uint32_t original, Packet &out) {
    if (size < 14) return false;
    size_t at = 12;
    uint16_t type = read16(data + at);
    while ((type == 0x8100 || type == 0x88a8) && at + 6 <= size) {
        at += 4;
        type = read16(data + at);
    }
    at += 2;
    out.length = original;
    out.kinds = 0;
    out.dport = -1;
    if (type == 0x0806) {
        if (size < at + 28 || read16(data + at + 2) != 0x0800 || data[at + 4] != 6 || data[at + 5] != 4) return false;
        uint16_t op = read16(data + at + 6);
        out.src = read32(data + at + 14);
        out.dst = read32(data + at + 24);
        if (op == 1) out.kinds = bit(kArpReq);
        if (op == 2) out.kinds = bit(kArpRep);
        return true;
    }
    if (type != 0x0800 || size < at + 20) return false;
    const uint8_t *ip = data + at;
    size_t header = static_cast<size_t>(ip[0] & 15) * 4;
    if (header < 20) return false;
    uint32_t total = read16(ip + 2);
    if (total == 0) total = original > at ? static_cast<uint32_t>(original - at) : 0;  // gói gộp TSO
    uint8_t proto = ip[9];
    bool later_fragment = (read16(ip + 6) & 0x1FFF) != 0;
    out.src = read32(ip + 12);
    out.dst = read32(ip + 16);
    const uint8_t *l4 = ip + header;
    size_t room = size > at + header ? size - at - header : 0;
    if (proto == 6) {
        out.kinds |= bit(kTcp);
        if (later_fragment || room < 14) return true;  // mảnh sau không có header TCP: không bật cờ nào
        out.dport = read16(l4 + 2);
        uint8_t flags = l4[13];
        uint32_t offset = static_cast<uint32_t>(l4[12] >> 4) * 4;
        uint32_t payload = total > header + offset ? total - static_cast<uint32_t>(header) - offset : 0;
        if ((flags & 0x12) == 0x02) out.kinds |= bit(kSyn);
        if ((flags & 0x12) == 0x12) out.kinds |= bit(kSynAck);
        if (flags & 0x04) out.kinds |= bit(kRst);
        if ((flags & 0x17) == 0x01) out.kinds |= bit(kFinOnly);
        if (flags == 0) out.kinds |= bit(kNull);
        if ((flags & 0x29) == 0x29) out.kinds |= bit(kXmas);
        if (flags == 0x10 && payload == 0) out.kinds |= bit(kAckOnly);
    } else if (proto == 17) {
        out.kinds |= bit(kUdp);
        if (!later_fragment && room >= 4) out.dport = read16(l4 + 2);
    } else if (proto == 1 && !later_fragment && room >= 1) {
        if (l4[0] == 8) out.kinds |= bit(kIcmpEcho);
        if (l4[0] == 3) out.kinds |= kIcmpUnreach;
    }
    return true;
}

// Tập phần tử một host đã gửi tới, cho biết còn bao nhiêu phần tử trong 60 s và 300 s gần nhất.
// Hàng đợi chỉ ghi tối đa mỗi giây một lần cho mỗi phần tử, nên phần tử có thể hết hạn sớm tối đa 1 s.
class Tracker {
public:
    bool touch(uint64_t key, double ts) {
        auto found = items_.find(key);
        if (found == items_.end()) {
            while (items_.size() >= kMaxItems) drop_oldest();  // phần tử mới luôn phải được theo dõi
            items_.emplace(key, Item{ts, ts, true});
            queue_.push_back({ts, key});
            ++short_count_;
            return true;
        }
        Item &item = found->second;
        bool fresh = ts - item.last > kNewGap;
        item.last = ts;
        if (!item.in_short) {
            item.in_short = true;
            ++short_count_;
            item.pushed = ts;
            queue_.push_back({ts, key});
        } else if (ts - item.pushed >= 1.0 && queue_.size() < kMaxQueue) {
            item.pushed = ts;
            queue_.push_back({ts, key});
        }
        return fresh;
    }

    void advance(double now) {
        while (cursor_ < queue_.size() && queue_[cursor_].ts <= now - kShort) {
            const Entry &entry = queue_[cursor_++];
            auto found = items_.find(entry.key);
            if (found != items_.end() && found->second.pushed == entry.ts && found->second.in_short) {
                found->second.in_short = false;
                --short_count_;
            }
        }
        while (!queue_.empty() && queue_.front().ts <= now - kLong) drop_oldest();
    }

    size_t in_short() const { return short_count_; }
    size_t in_long() const { return items_.size(); }

private:
    struct Item {
        double last, pushed;
        bool in_short;
    };
    struct Entry {
        double ts;
        uint64_t key;
    };

    void drop_oldest() {
        const Entry entry = queue_.front();
        queue_.pop_front();
        if (cursor_ > 0) --cursor_;
        auto found = items_.find(entry.key);
        if (found != items_.end() && found->second.pushed == entry.ts) {
            if (found->second.in_short) --short_count_;
            items_.erase(found);
        }
    }

    std::unordered_map<uint64_t, Item> items_;
    std::deque<Entry> queue_;
    size_t cursor_ = 0, short_count_ = 0;
};

// Bộ đếm mỗi giây: gói gửi, byte, 12 loại gói, rồi 4 bộ đếm chiều nhận.
enum Counter { kPkts = 0, kFirstKind = 1, kRxPkts = 1 + kKinds, kRxRst, kRxSynAck, kRxUnreach, kCounters };
struct Totals {
    std::array<uint32_t, kCounters> counts{};
    double bytes = 0;
    void add(const Totals &other) {
        for (size_t i = 0; i < kCounters; ++i) counts[i] += other.counts[i];
        bytes += other.bytes;
    }
    void remove(const Totals &other) {
        for (size_t i = 0; i < kCounters; ++i) counts[i] -= other.counts[i];
        bytes -= other.bytes;
    }
};
struct Bin {
    int64_t second;
    Totals totals;
};

struct Episode {
    bool active = false;
    double start = 0, last = 0;
    float top = 0;
    uint32_t windows = 0;
    std::array<uint32_t, 3> classes{};
};

struct Host {
    uint32_t ip = 0;
    bool open = false;
    double t_first = 0;
    size_t count = 0;
    std::array<double, kPackets> times{};
    std::array<uint32_t, kPackets> lengths{};
    std::array<uint32_t, kPackets> targets{};
    std::array<int32_t, kPackets> ports{};
    std::array<uint16_t, kPackets> kinds{};
    uint32_t new_dst = 0, new_pair = 0, new_port = 0;
    uint32_t rx_all = 0, rx_rst = 0, rx_synack = 0, rx_unreach = 0;

    std::deque<Bin> bins;
    size_t short_cursor = 0;
    Totals short_totals, long_totals;
    Tracker dst, pair, port, syn_pair, arp, icmp;
    Episode episode;

    // Thống kê bảng trạng thái theo CHU KỲ hiện tại (reset sau mỗi lần in), để phản ánh đúng thời điểm.
    // cur_class: 0=benign,1=recon,2=bruteforce,3=dos — lớp tại cửa sổ có điểm cao nhất trong chu kỳ.
    uint64_t windows_seen = 0;  // tổng từ đầu, cho stats chung
    float cur_peak = 0;
    uint8_t cur_class = 0;
    uint32_t cur_windows = 0;
    double last_seen = 0;

    Totals &tick(int64_t second) {
        if (bins.empty() || bins.back().second != second) bins.push_back({second, {}});
        return bins.back().totals;
    }

    void advance(double now) {
        const int64_t second = static_cast<int64_t>(std::floor(now));
        while (short_cursor < bins.size() && bins[short_cursor].second <= second - static_cast<int64_t>(kShort))
            short_totals.remove(bins[short_cursor++].totals);
        while (!bins.empty() && bins.front().second <= second - static_cast<int64_t>(kLong)) {
            long_totals.remove(bins.front().totals);
            bins.pop_front();
            if (short_cursor > 0) --short_cursor;
        }
        for (Tracker *tracker : {&dst, &pair, &port, &syn_pair, &arp, &icmp}) tracker->advance(now);
    }
};

std::vector<std::string> feature_names() {
    std::vector<std::string> names = {"f_w_pkts", "f_w_by_count", "f_w_dur", "f_w_span", "f_w_pps", "f_w_iat_mean",
                                      "f_w_iat_std", "f_w_iat_max", "f_w_len_mean", "f_w_len_std", "f_w_len_min", "f_w_len_max"};
    for (const char *kind : kKindNames) names.push_back(std::string("f_w_r_") + kind);
    for (const char *name : {"f_w_rx_ratio", "f_w_rx_rst_ratio", "f_w_rx_synack_ratio", "f_w_rx_unreach_ratio", "f_w_d_dst",
                             "f_w_d_pair", "f_w_d_port", "f_w_d_syn_pair", "f_w_d_arp", "f_w_d_icmp", "f_w_new_dst_ratio",
                             "f_w_new_pair_ratio", "f_w_new_port_ratio"})
        names.push_back(name);
    for (const char *span : {"60", "300"}) {
        std::vector<std::string> part = {"f_pkts", "f_bytes"};
        for (const char *kind : kKindNames) part.push_back(std::string("f_") + kind);
        for (const char *name : {"f_rx_pkts", "f_rx_rst", "f_rx_synack", "f_rx_icmp_unreach", "f_d_dst", "f_d_pair", "f_d_port",
                                 "f_d_syn_pair", "f_d_arp", "f_d_icmp", "f_syn_ratio", "f_rx_rst_ratio", "f_rx_unreach_ratio",
                                 "f_syn_per_pair", "f_port_per_dst", "f_bytes_per_pkt"})
            part.push_back(name);
        for (const auto &name : part) names.push_back(name + "_" + span);
    }
    return names;
}

class MappedFile {
public:
    explicit MappedFile(const std::string &path) {
        int fd = open(path.c_str(), O_RDONLY);
        if (fd < 0) throw std::runtime_error("khong mo duoc " + path);
        struct stat st {};
        fstat(fd, &st);
        size_ = static_cast<size_t>(st.st_size);
        data_ = mmap(nullptr, size_, PROT_READ, MAP_SHARED, fd, 0);
        close(fd);
        if (data_ == MAP_FAILED) throw std::runtime_error("mmap that bai: " + path);
    }
    void *data() const { return data_; }
    size_t size() const { return size_; }

private:
    void *data_ = nullptr;
    size_t size_ = 0;
};

Ort::SessionOptions session_options() {
    Ort::SessionOptions options;
    options.SetIntraOpNumThreads(1);
    options.SetInterOpNumThreads(1);
    options.DisableCpuMemArena();
    options.DisableMemPattern();
    options.AddConfigEntry("session.use_ort_model_bytes_directly", "1");
    options.AddConfigEntry("session.use_ort_model_bytes_for_initializers", "1");
    return options;
}

class Model {
public:
    Model(Ort::Env &env, const std::string &path)
        : file_(path), session_(env, file_.data(), file_.size(), session_options()),
          memory_(Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault)) {}

    std::array<float, kClasses> predict(std::array<float, kFeatures> &values) {
        const std::array<int64_t, 2> shape = {1, static_cast<int64_t>(kFeatures)};
        Ort::Value input = Ort::Value::CreateTensor<float>(memory_, values.data(), kFeatures, shape.data(), shape.size());
        const char *in[] = {"features"};
        const char *out[] = {"probabilities"};
        auto got = session_.Run(Ort::RunOptions{nullptr}, in, &input, 1, out, 1);
        const float *proba = got[0].GetTensorData<float>();
        return {proba[0], proba[1], proba[2], proba[3]};
    }

private:
    MappedFile file_;
    Ort::Session session_;
    Ort::MemoryInfo memory_;
};

struct Options {
    std::string model, output, windows;
    double threshold = kDefaultThreshold;
    uint32_t prefix = parse_ip("192.168.1.0") & 0xFFFFFF00;
    std::set<uint32_t> only, skip;
    bool features = false, quiet = false, status = false, live = false;
    uint32_t interval = kStatsSeconds;  // giây giữa hai lần in stats/bảng
};

class Detector {
public:
    Detector(Model &model, const Options &options) : model_(model), options_(options) {
        if (!options.output.empty()) alerts_.open(options.output, std::ios::app);
        if (!options.windows.empty()) {
            windows_.open(options.windows);
            windows_ << "host,t_first,t_end,score,alarm,attack_class,p_benign,p_recon,p_bruteforce,p_dos,infer_us";
            if (options.features)
                for (const auto &name : feature_names()) windows_ << ',' << name;
            windows_ << '\n';
        }
    }

    void add(Packet packet) {
        packet.ts = std::max(packet.ts, clock_);  // tcpdump nhiều nhân đôi khi đảo nhẹ thứ tự
        clock_ = packet.ts;
        ++packets_;
        if (packet.ts > deadline_) close_expired(packet.ts);
        if (in_lan(packet.src) && wanted(packet.src)) add_sent(host(packet.src), packet);
        if (in_lan(packet.dst) && wanted(packet.dst)) add_received(host(packet.dst), packet);
    }

    // Mạng im lặng: đồng hồ vẫn phải chạy để chốt cửa sổ theo thời gian và kết thúc đợt.
    void tick(double now) {
        if (now <= clock_) return;
        clock_ = now;
        if (now > deadline_) close_expired(now);
        end_episodes(now, false);
    }

    void finish() {
        for (auto &item : hosts_)
            if (item && item->open) close_window(*item, item->t_first + kMaxSeconds, false);
        end_episodes(clock_, true);
    }

    void stats() {
        size_t active = 0;
        for (const auto &item : hosts_) active += item != nullptr;
        const double average = windows_done_ ? infer_total_ / static_cast<double>(windows_done_) : 0;
        std::fprintf(stderr, "   [%s] goi %s | cua so %s | bao dong %s | dot %s | host %zu | suy luan %.1fms (dinh %.0fms)\n",
                     hms(clock_).c_str(), commas(packets_).c_str(), commas(windows_done_).c_str(),
                     commas(alarms_).c_str(), commas(episodes_).c_str(), active, average / 1000.0, infer_max_ / 1000.0);
        if (options_.status) status();
    }

    // Bảng trạng thái theo thời gian thực: chỉ host có hoạt động trong CHU KỲ vừa rồi, lớp + điểm đỉnh
    // của chu kỳ đó. In xong thì reset, nên host ngừng tấn công sẽ về benign/biến mất ngay chu kỳ sau.
    void status() {
        static const char *const names[4] = {"benign", "recon", "bruteforce", "dos"};
        std::vector<Host *> active;
        for (auto &item : hosts_)
            if (item && item->cur_windows) active.push_back(item.get());
        std::sort(active.begin(), active.end(),
                  [](const Host *a, const Host *b) { return a->cur_peak > b->cur_peak; });
        std::fprintf(stderr, "   %-15s  %-10s  %6s  %s\n", "host", "lop", "diem", "cua so");
        if (active.empty()) std::fprintf(stderr, "   (khong co host nao hoat dong)\n");
        size_t shown = 0;
        for (Host *h : active) {
            if (shown < 20)
                std::fprintf(stderr, "   %-15s  %-10s  %5.0f%%  %u\n", ip_text(h->ip).c_str(), names[h->cur_class],
                             h->cur_peak * 100.0, h->cur_windows);
            ++shown;
        }
        if (shown > 20) std::fprintf(stderr, "   ... va %zu host khac\n", shown - 20);
        for (auto &item : hosts_)  // reset cho chu kỳ sau
            if (item) {
                item->cur_windows = 0;
                item->cur_peak = 0;
                item->cur_class = 0;
            }
    }

private:
    bool in_lan(uint32_t ip) const { return (ip & 0xFFFFFF00) == options_.prefix; }
    bool wanted(uint32_t ip) const {
        return (options_.only.empty() || options_.only.count(ip)) && !options_.skip.count(ip);
    }

    Host &host(uint32_t ip) {
        auto &slot = hosts_[ip & 255];
        if (!slot) {
            slot = std::make_unique<Host>();
            slot->ip = ip;
        }
        return *slot;
    }

    void add_sent(Host &item, const Packet &packet) {
        if (!item.open) {
            item.open = true;
            item.t_first = packet.ts;
            item.count = 0;
            item.new_dst = item.new_pair = item.new_port = 0;
            item.rx_all = item.rx_rst = item.rx_synack = item.rx_unreach = 0;
            deadline_ = std::min(deadline_, packet.ts + kMaxSeconds);
        }
        const size_t slot = item.count++;
        item.times[slot] = packet.ts;
        item.lengths[slot] = packet.length;
        item.targets[slot] = packet.dst;
        item.ports[slot] = packet.dport;
        item.kinds[slot] = packet.kinds;

        item.new_dst += item.dst.touch(packet.dst, packet.ts);
        if (packet.dport >= 0) {
            const uint64_t pair = static_cast<uint64_t>(packet.dst) << 16 | static_cast<uint32_t>(packet.dport);
            item.new_pair += item.pair.touch(pair, packet.ts);
            item.new_port += item.port.touch(static_cast<uint32_t>(packet.dport), packet.ts);
            if (packet.kinds & bit(kSyn)) item.syn_pair.touch(pair, packet.ts);
        }
        if (packet.kinds & bit(kArpReq)) item.arp.touch(packet.dst, packet.ts);
        if (packet.kinds & bit(kIcmpEcho)) item.icmp.touch(packet.dst, packet.ts);

        Totals change;
        change.counts[kPkts] = 1;
        change.bytes = packet.length;
        for (size_t kind = 0; kind < kKinds; ++kind)
            if (packet.kinds & (1u << kind)) change.counts[kFirstKind + kind] = 1;
        record(item, packet.ts, change);

        if (item.count == kPackets) close_window(item, packet.ts, true);
    }

    void add_received(Host &item, const Packet &packet) {
        const bool rst = packet.kinds & bit(kRst), synack = packet.kinds & bit(kSynAck), unreach = packet.kinds & kIcmpUnreach;
        Totals change;
        change.counts[kRxPkts] = 1;
        change.counts[kRxRst] = rst;
        change.counts[kRxSynAck] = synack;
        change.counts[kRxUnreach] = unreach;
        record(item, packet.ts, change);
        if (item.open) {
            ++item.rx_all;
            item.rx_rst += rst;
            item.rx_synack += synack;
            item.rx_unreach += unreach;
        }
    }

    static void record(Host &item, double ts, const Totals &change) {
        const int64_t second = static_cast<int64_t>(std::floor(ts));
        item.tick(second).add(change);
        item.short_totals.add(change);
        item.long_totals.add(change);
    }

    void close_expired(double now) {
        double next = kNever;
        for (auto &item : hosts_) {
            if (!item || !item->open) continue;
            if (item->t_first + kMaxSeconds < now)
                close_window(*item, item->t_first + kMaxSeconds, false);
            else
                next = std::min(next, item->t_first + kMaxSeconds);
        }
        deadline_ = next;
    }

    template <typename Pick>
    static size_t distinct(const Host &item, uint16_t need, Pick pick) {
        std::array<uint64_t, kPackets> values;
        size_t size = 0;
        for (size_t i = 0; i < item.count; ++i)
            if ((need == 0 || (item.kinds[i] & need)) && pick(i, values[size])) ++size;
        std::sort(values.begin(), values.begin() + size);
        return static_cast<size_t>(std::unique(values.begin(), values.begin() + size) - values.begin());
    }

    void close_window(Host &item, double t_end, bool by_count) {
        item.open = false;
        item.advance(t_end);
        const size_t count = item.count;
        const double t_first = item.times[0], t_last = item.times[count - 1], duration = t_end - t_first;
        const double scale = static_cast<double>(count);

        double gap_sum = 0, gap_max = 0, gap_squares = 0, len_sum = 0, len_squares = 0;
        double len_min = item.lengths[0], len_max = item.lengths[0];
        std::array<uint32_t, kKinds> kinds{};
        for (size_t i = 0; i < count; ++i) {
            const double length = item.lengths[i];
            len_sum += length;
            len_squares += length * length;
            len_min = std::min(len_min, length);
            len_max = std::max(len_max, length);
            for (size_t kind = 0; kind < kKinds; ++kind) kinds[kind] += (item.kinds[i] >> kind) & 1;
            if (i) {
                const double gap = item.times[i] - item.times[i - 1];
                gap_sum += gap;
                gap_squares += gap * gap;
                gap_max = std::max(gap_max, gap);
            }
        }
        const double gaps = static_cast<double>(count - 1);
        const double gap_mean = count > 1 ? gap_sum / gaps : 0;
        const double gap_std = count > 1 ? std::sqrt(std::max(0.0, gap_squares / gaps - gap_mean * gap_mean)) : 0;
        const double len_mean = len_sum / scale;
        const double len_std = std::sqrt(std::max(0.0, len_squares / scale - len_mean * len_mean));

        std::array<float, kFeatures> f;
        size_t n = 0;
        auto push = [&](double value) { f[n++] = static_cast<float>(value); };
        push(scale);
        push(by_count);
        push(duration);
        push(t_last - t_first);
        push(scale / std::max(duration, 0.001));
        push(gap_mean);
        push(gap_std);
        push(gap_max);
        push(len_mean);
        push(len_std);
        push(len_min);
        push(len_max);
        for (uint32_t value : kinds) push(value / scale);
        push(item.rx_all / scale);
        push(item.rx_rst / scale);
        push(item.rx_synack / scale);
        push(item.rx_unreach / scale);
        auto target = [&](size_t i, uint64_t &out) { out = item.targets[i]; return true; };
        auto pair = [&](size_t i, uint64_t &out) {
            out = static_cast<uint64_t>(item.targets[i]) << 16 | static_cast<uint32_t>(item.ports[i] & 0xFFFF);
            return item.ports[i] >= 0;
        };
        auto port = [&](size_t i, uint64_t &out) { out = static_cast<uint32_t>(item.ports[i] & 0xFFFF); return item.ports[i] >= 0; };
        push(distinct(item, 0, target));
        push(distinct(item, 0, pair));
        push(distinct(item, 0, port));
        push(distinct(item, bit(kSyn), pair));
        push(distinct(item, bit(kArpReq), target));
        push(distinct(item, bit(kIcmpEcho), target));
        push(item.new_dst / scale);
        push(item.new_pair / scale);
        push(item.new_port / scale);
        context(item, item.short_totals, false, push);
        context(item, item.long_totals, true, push);
        if (n != kFeatures) throw std::logic_error("sai so dac trung");

        const auto start = std::chrono::steady_clock::now();
        const auto proba = model_.predict(f);
        const double micros = std::chrono::duration<double, std::micro>(std::chrono::steady_clock::now() - start).count();
        infer_total_ += micros;
        infer_max_ = std::max(infer_max_, micros);
        ++windows_done_;

        const double score = 1.0 - static_cast<double>(proba[0]);
        const bool alarm = score >= options_.threshold;
        const size_t attack = static_cast<size_t>(std::max_element(proba.begin() + 1, proba.end()) - proba.begin() - 1);
        // Lớp dự đoán cho bảng trạng thái: benign nếu chưa vượt ngưỡng, ngược lại là lớp tấn công.
        ++item.windows_seen;
        ++item.cur_windows;
        item.last_seen = t_end;
        if (static_cast<float>(score) >= item.cur_peak) {
            item.cur_peak = static_cast<float>(score);
            item.cur_class = static_cast<uint8_t>(alarm ? attack + 1 : 0);
        }
        if (alarm) raise(item, t_end, attack, static_cast<float>(score));
        if (windows_.is_open()) log_window(item, t_first, t_end, score, alarm, attack, proba, micros, f);
    }

    template <typename Push>
    void context(const Host &item, const Totals &totals, bool longer, Push &push) const {
        const auto &c = totals.counts;
        const auto seen = [&](const Tracker &tracker) { return static_cast<double>(longer ? tracker.in_long() : tracker.in_short()); };
        const double pkts = c[kPkts], d_syn = seen(item.syn_pair), d_port = seen(item.port), d_dst = seen(item.dst);
        const double syn = c[kFirstKind + kSyn], tcp = c[kFirstKind + kTcp];
        push(pkts);
        push(totals.bytes);
        for (size_t kind = 0; kind < kKinds; ++kind) push(c[kFirstKind + kind]);
        push(c[kRxPkts]);
        push(c[kRxRst]);
        push(c[kRxSynAck]);
        push(c[kRxUnreach]);
        push(d_dst);
        push(seen(item.pair));
        push(d_port);
        push(d_syn);
        push(seen(item.arp));
        push(seen(item.icmp));
        push(syn / std::max(tcp, 1.0));
        push(c[kRxRst] / std::max(pkts, 1.0));
        push(c[kRxUnreach] / std::max(pkts, 1.0));
        push(syn / std::max(d_syn, 1.0));
        push(d_port / std::max(d_dst, 1.0));
        push(totals.bytes / std::max(pkts, 1.0));
    }

    void log_window(const Host &item, double t_first, double t_end, double score, bool alarm, size_t attack,
                    const std::array<float, kClasses> &proba, double micros, const std::array<float, kFeatures> &f) {
        char line[256];
        std::snprintf(line, sizeof line, "%s,%.6f,%.6f,%.6f,%d,%s,%.6f,%.6f,%.6f,%.6f,%.0f", ip_text(item.ip).c_str(), t_first, t_end,
                      score, alarm, kClassNames[attack], proba[0], proba[1], proba[2], proba[3], micros);
        windows_ << line;
        if (options_.features)
            for (float value : f) {
                std::snprintf(line, sizeof line, ",%.9g", value);
                windows_ << line;
            }
        windows_ << '\n';
    }

    void raise(Host &item, double t_end, size_t attack, float score) {
        ++alarms_;
        Episode &episode = item.episode;
        if (episode.active && t_end - episode.last > kEpisodeGap) end_episode(item);
        if (!episode.active) {
            episode = Episode{};
            episode.active = true;
            episode.start = t_end;
            ++episodes_;
            const std::string ip = ip_text(item.ip);
            char json[200], pretty[160];
            std::snprintf(json, sizeof json,
                          "{\"event\":\"attack_start\",\"time\":\"%s\",\"ts\":%.3f,\"host\":\"%s\",\"class\":\"%s\",\"score\":%.4f}\n",
                          iso_time(t_end).c_str(), t_end, ip.c_str(), kClassNames[attack], score);
            std::snprintf(pretty, sizeof pretty, ">> [%s] BAO DONG  %-15s  %-10s  diem %.2f",
                          hms(t_end).c_str(), ip.c_str(), upper(kClassNames[attack]).c_str(), score);
            emit(json, pretty);
        }
        episode.last = t_end;
        episode.top = std::max(episode.top, score);
        ++episode.windows;
        ++episode.classes[attack];
    }

    void end_episode(Host &item) {
        Episode &episode = item.episode;
        const size_t best = static_cast<size_t>(std::max_element(episode.classes.begin(), episode.classes.end()) - episode.classes.begin());
        const std::string ip = ip_text(item.ip);
        char json[320], pretty[200];
        std::snprintf(json, sizeof json,
                      "{\"event\":\"attack_end\",\"time\":\"%s\",\"host\":\"%s\",\"class\":\"%s\",\"start\":\"%s\",\"duration_s\":%.1f,"
                      "\"windows\":%u,\"recon\":%u,\"bruteforce\":%u,\"dos\":%u,\"max_score\":%.4f}\n",
                      iso_time(episode.last).c_str(), ip.c_str(), kClassNames[best], iso_time(episode.start).c_str(),
                      episode.last - episode.start, episode.windows, episode.classes[0], episode.classes[1], episode.classes[2], episode.top);
        std::snprintf(pretty, sizeof pretty, "<< [%s] ket thuc  %-15s  %-10s  %.0fs, %u cua so, diem cao nhat %.2f",
                      hms(episode.last).c_str(), ip.c_str(), upper(kClassNames[best]).c_str(),
                      episode.last - episode.start, episode.windows, episode.top);
        emit(json, pretty);
        episode.active = false;
    }

    void end_episodes(double now, bool all) {
        for (auto &item : hosts_)
            if (item && item->episode.active && (all || now - item->episode.last > kEpisodeGap)) end_episode(*item);
    }

    // Console nhận dòng gọn cho người đọc; file --output giữ JSON cho máy phân tích.
    // Ở chế độ --live (vẽ lại bảng), bỏ dòng cuộn ra console để không bị xoá; cảnh báo vẫn vào file.
    void emit(const char *json, const char *pretty) {
        if (!options_.quiet && !options_.live) std::cout << pretty << "\n" << std::flush;
        if (alerts_) alerts_ << json << std::flush;
    }

    static constexpr double kNever = 1e300;
    Model &model_;
    const Options &options_;
    std::array<std::unique_ptr<Host>, 256> hosts_;
    std::ofstream alerts_, windows_;
    double clock_ = 0, deadline_ = kNever, infer_total_ = 0, infer_max_ = 0;
    uint64_t packets_ = 0, windows_done_ = 0, alarms_ = 0, episodes_ = 0;
};

// Đọc stdin theo khối, gọi on_idle mỗi giây khi không có gói.
class Input {
public:
    template <typename Idle>
    bool read(void *target, size_t size, Idle on_idle) {
        auto *out = static_cast<uint8_t *>(target);
        while (size > 0) {
            if (begin_ == end_) {
                struct pollfd wait {STDIN_FILENO, POLLIN, 0};
                int ready = poll(&wait, 1, kPollMilliseconds);
                if (ready == 0) {
                    on_idle();
                    continue;
                }
                if (ready < 0) continue;
                ssize_t got = ::read(STDIN_FILENO, buffer_.data(), buffer_.size());
                if (got <= 0) return false;
                begin_ = 0;
                end_ = static_cast<size_t>(got);
            }
            size_t step = std::min(size, end_ - begin_);
            std::memcpy(out, buffer_.data() + begin_, step);
            begin_ += step;
            out += step;
            size -= step;
        }
        return true;
    }

private:
    std::vector<uint8_t> buffer_ = std::vector<uint8_t>(262144);
    size_t begin_ = 0, end_ = 0;
};

int run(const Options &options) {
    Input input;
    uint32_t header[6];
    if (!input.read(header, sizeof header, [] {})) {
        std::cerr << "khong doc duoc pcap header tu stdin\n";
        return 1;
    }
    const bool swapped = header[0] == swap32(kMagicMicro) || header[0] == swap32(kMagicNano);
    const uint32_t magic = swapped ? swap32(header[0]) : header[0];
    const uint32_t link = swapped ? swap32(header[5]) : header[5];
    if ((magic != kMagicMicro && magic != kMagicNano) || (link & 0xFFFF) != kLinkEthernet) {
        std::cerr << "chi ho tro pcap Ethernet, link=" << link << "\n";
        return 1;
    }
    const double fraction = magic == kMagicNano ? 1e-9 : 1e-6;

    Ort::Env env(ORT_LOGGING_LEVEL_ERROR, "ids");
    Model model(env, options.model);
    Detector detector(model, options);
    std::cerr << "ids_agent san sang, nguong=" << options.threshold << "\n";

    std::vector<uint8_t> frame(kMaxFrame);
    double last_packet = 0;
    std::time_t last_wall = 0, last_stats = std::time(nullptr);
    auto report = [&] {
        const std::time_t now = std::time(nullptr);
        if (now - last_stats >= static_cast<std::time_t>(options.interval)) {
            if (options.live) std::cerr << "\033[2J\033[H";  // xoá màn hình, vẽ lại như top
            detector.stats();
            last_stats = now;
        }
    };
    auto on_idle = [&] {
        if (last_wall) detector.tick(last_packet + static_cast<double>(std::time(nullptr) - last_wall));
        report();
    };

    uint32_t record[4];
    while (input.read(record, sizeof record, on_idle)) {
        const uint32_t seconds = swapped ? swap32(record[0]) : record[0];
        const uint32_t part = swapped ? swap32(record[1]) : record[1];
        const uint32_t captured = swapped ? swap32(record[2]) : record[2];
        const uint32_t original = swapped ? swap32(record[3]) : record[3];
        if (captured > kMaxFrame) {
            std::cerr << "pcap hong: captured=" << captured << "\n";
            return 1;
        }
        if (!input.read(frame.data(), captured, on_idle)) break;
        Packet packet;
        packet.ts = static_cast<double>(seconds) + part * fraction;
        last_packet = packet.ts;
        last_wall = std::time(nullptr);
        if (parse_frame(frame.data(), captured, original, packet)) detector.add(packet);
        report();
    }
    detector.finish();
    detector.stats();
    return 0;
}

const char kUsage[] =
    "usage: ids_agent <ids_model.ort> [--threshold x] [--lan-prefix 192.168.1.] [--output alerts.jsonl]\n"
    "                 [--windows windows.csv] [--features] [--status] [--live] [--interval giay]\n"
    "                 [--host ip] [--exclude ip] [--quiet]\n"
    "       ids_agent --print-features\n";

}  // namespace

int main(int argc, char **argv) {
    if (argc < 2) {
        std::cerr << kUsage;
        return 2;
    }
    if (std::string(argv[1]) == "--print-features") {
        for (const auto &name : feature_names()) std::cout << name << "\n";
        return 0;
    }
    // Ctrl+C dừng tcpdump; agent đọc tới hết stdin để kết thúc các đợt còn mở rồi mới thoát.
    std::signal(SIGINT, SIG_IGN);
    try {
        Options options;
        options.model = argv[1];
        for (int i = 2; i < argc; ++i) {
            const std::string key = argv[i];
            auto next = [&]() -> std::string {
                if (i + 1 >= argc) throw std::runtime_error("thieu gia tri cho " + key);
                return argv[++i];
            };
            if (key == "--threshold") options.threshold = std::strtod(next().c_str(), nullptr);
            else if (key == "--lan-prefix") options.prefix = parse_ip(next()) & 0xFFFFFF00;
            else if (key == "--output") options.output = next();
            else if (key == "--windows") options.windows = next();
            else if (key == "--features") options.features = true;
            else if (key == "--status") options.status = true;
            else if (key == "--live") { options.live = true; options.status = true; }
            else if (key == "--interval") options.interval = std::max(1u, static_cast<uint32_t>(std::strtoul(next().c_str(), nullptr, 10)));
            else if (key == "--host") options.only.insert(parse_ip(next()));
            else if (key == "--exclude") options.skip.insert(parse_ip(next()));
            else if (key == "--quiet") options.quiet = true;
            else throw std::runtime_error("tham so la: " + key);
        }
        return run(options);
    } catch (const std::exception &error) {
        std::cerr << "LOI: " << error.what() << "\n";
        return 1;
    }
}
