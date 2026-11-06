#include "feature_extract.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>

namespace sdc {
namespace {

const char *const kMissing = "<missing>";
constexpr size_t kMaxTokens = 40;
constexpr size_t kMaxHello = 16384;
constexpr size_t kMaxPending = 256;
constexpr uint32_t kHelloTimeout = 5;
constexpr uint16_t kEtherIpv4 = 0x0800, kEtherIpv6 = 0x86DD, kEtherVlan = 0x8100, kEtherQinq = 0x88A8;
constexpr uint8_t kTcp = 6, kUdp = 17;
constexpr uint16_t kTypeTxt = 16;
constexpr int kQuestion = 0;
constexpr uint8_t kDhcpDiscover = 1, kDhcpRequest = 3;

uint16_t be16(const uint8_t *p) { return static_cast<uint16_t>(p[0] << 8 | p[1]); }
uint32_t be32(const uint8_t *p) {
    return static_cast<uint32_t>(p[0]) << 24 | p[1] << 16 | p[2] << 8 | p[3];
}

std::string lower_ascii(std::string text) {
    for (char &c : text)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
    return text;
}

bool is_space(char c) { return c == ' ' || (c >= '\t' && c <= '\r') || (c >= 0x1c && c <= 0x1f); }

std::string join_numbers(const std::vector<uint32_t> &values) {
    std::string out;
    for (size_t i = 0; i < values.size(); ++i) {
        if (i) out += ',';
        out += std::to_string(values[i]);
    }
    return out;
}

// GREASE RFC 8701: 0x0a0a, 0x1a1a, ... 0xfafa
bool is_grease(uint16_t value) {
    return (value & 0x0f0f) == 0x0a0a && (value >> 8) == (value & 0xff);
}

// Đọc tên DNS, có nén con trỏ. Trả false nếu gói hỏng.
bool read_name(const uint8_t *data, size_t length, size_t &offset, std::string &name) {
    size_t at = offset;
    bool jumped = false;
    int hops = 0;
    name.clear();
    while (true) {
        if (at >= length) return false;
        uint8_t size = data[at];
        if (size == 0) {
            if (!jumped) offset = at + 1;
            return true;
        }
        if ((size & 0xC0) == 0xC0) {
            if (at + 1 >= length || ++hops > 16) return false;
            size_t target = static_cast<size_t>(size & 0x3F) << 8 | data[at + 1];
            if (!jumped) offset = at + 2;
            jumped = true;
            at = target;
            continue;
        }
        if ((size & 0xC0) != 0 || at + 1 + size > length) return false;
        if (!name.empty()) name += '.';
        name.append(reinterpret_cast<const char *>(data + at + 1), size);
        at += 1 + size;
        if (name.size() > 1024) return false;
    }
}

// TXT trong observation: các chuỗi nối bằng dấu `;`
std::string txt_value(const uint8_t *data, size_t length) {
    std::string value;
    size_t at = 0;
    while (at < length) {
        size_t size = data[at];
        if (at + 1 + size > length) break;
        if (!value.empty()) value += ';';
        value.append(reinterpret_cast<const char *>(data + at + 1), size);
        at += 1 + size;
    }
    return value;
}

}  // namespace

std::string mac_text(const Mac &mac) {
    char text[18];
    std::snprintf(text, sizeof text, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4],
                  mac[5]);
    return text;
}

// Byte không phải UTF-8 hợp lệ đổi thành `?` để ONNX Runtime không báo lỗi chuỗi hỏng.
std::string sanitize_utf8(const std::string &value) {
    std::string out;
    out.reserve(value.size());
    const auto *s = reinterpret_cast<const uint8_t *>(value.data());
    size_t i = 0, n = value.size();
    while (i < n) {
        uint8_t c = s[i];
        size_t extra = c < 0x80 ? 0 : (c >> 5) == 0x6 ? 1 : (c >> 4) == 0xE ? 2 : (c >> 3) == 0x1E ? 3 : 4;
        bool ok = extra < 4 && i + extra < n + (extra == 0 ? 1 : 0);
        for (size_t k = 1; ok && k <= extra; ++k) ok = (s[i + k] & 0xC0) == 0x80;
        if (ok && c != 0) {
            out.append(value, i, extra + 1);
            i += extra + 1;
        } else {
            out += '?';
            ++i;
        }
    }
    return out;
}

// Bản Python dùng NFKC. Router không có bảng Unicode nên chỉ xử lý ASCII: chữ thường,
// bỏ khoảng trắng hai đầu, gộp khoảng trắng. Ký tự ngoài ASCII giữ nguyên.
std::string normalize_hostname(const std::string &value) {
    std::string out;
    bool pending_space = false;
    for (char c : value) {
        if (is_space(c)) {
            pending_space = !out.empty();
            continue;
        }
        if (pending_space) out += ' ';
        pending_space = false;
        out += c;
    }
    out = lower_ascii(out);
    static const char *const nulls[] = {"null", "none", "nan", "<missing>", "<na>", "__unknown__"};
    for (const char *null : nulls)
        if (out == null) return "";
    return out;
}

void ModeCounter::add(const std::string &value) {
    bool blank = std::all_of(value.begin(), value.end(), is_space);
    if (!blank) ++counts_[value];
}

std::string ModeCounter::best() const {
    std::string winner = kMissing;
    uint32_t peak = 0;
    for (const auto &[value, count] : counts_) {  // map đã sắp xếp nên hoà thì giá trị đầu thắng
        if (count > peak) {
            peak = count;
            winner = value;
        }
    }
    return winner;
}

void TokenSet::add_name(const std::string &name) {
    if (tokens_.size() >= kMaxTokens) return;
    std::string text = lower_ascii(name);
    while (!text.empty() && text.back() == '.') text.pop_back();
    size_t start = 0;
    for (size_t i = 0; i <= text.size(); ++i) {
        if (i == text.size() || text[i] == '.' || text[i] == '-') {
            if (i > start) {
                std::string token = text.substr(start, i - start);
                if (std::find(tokens_.begin(), tokens_.end(), token) == tokens_.end()) {
                    tokens_.push_back(std::move(token));
                    if (tokens_.size() >= kMaxTokens) return;
                }
            }
            start = i + 1;
        }
    }
}

std::string TokenSet::text() const {
    if (tokens_.empty()) return kMissing;
    std::string out;
    for (size_t i = 0; i < tokens_.size(); ++i) {
        if (i) out += ' ';
        out += tokens_[i];
    }
    return out;
}

FeatureExtractor::FeatureExtractor()
    : model_re_("(?i)(?:^|[;\\s])model=([^;\\s]+)"),
      cast_re_("(?i)(?:^|;)md=([^;]+)"),
      mi_re_("(?i)\\{.*?\"nm\"\\s*:\\s*\"([^\"]+)\".*\\}\\._mi-connect\\._udp\\.local\\.?") {}

std::map<Mac, DeviceWindow> FeatureExtractor::take_window() {
    std::map<Mac, DeviceWindow> out;
    out.swap(devices_);
    return out;
}

void FeatureExtractor::enable_trigger(uint32_t timeout, uint32_t cooldown) {
    trigger_ = true;
    timeout_ = timeout;
    cooldown_ = cooldown;
}

DeviceWindow *FeatureExtractor::session(const Mac &mac) {
    if (!trigger_) return &devices_[mac];
    auto found = devices_.find(mac);
    return found == devices_.end() ? nullptr : &found->second;
}

std::vector<FinishedSession> FeatureExtractor::take_finished(uint32_t now, bool final) {
    std::vector<FinishedSession> done;
    for (auto it = devices_.begin(); it != devices_.end();) {
        const char *reason = it->second.all_sources()             ? "complete"
                             : now - it->second.start >= timeout_ ? "timeout"
                             : final                              ? "eof"
                                                                  : nullptr;
        if (reason == nullptr) {
            ++it;
            continue;
        }
        finished_at_[it->first] = now;
        done.push_back({it->first, std::move(it->second), reason, now});
        it = devices_.erase(it);
    }
    return done;
}

void FeatureExtractor::add_frame(const uint8_t *data, size_t length, uint32_t seconds) {
    ++frames_;
    now_ = seconds;
    if (length < 14) return;
    Mac src;
    std::memcpy(src.data(), data + 6, 6);
    size_t at = 12;
    uint16_t ether = be16(data + at);
    at += 2;
    while ((ether == kEtherVlan || ether == kEtherQinq) && at + 4 <= length) {
        ether = be16(data + at + 2);
        at += 4;
    }

    uint8_t proto = 0;
    size_t ip_payload = 0;
    std::string flow;
    if (ether == kEtherIpv4) {
        if (at + 20 > length || (data[at] >> 4) != 4) return;
        size_t header = static_cast<size_t>(data[at] & 0x0F) * 4;
        uint16_t fragment = be16(data + at + 6);
        if (header < 20 || (fragment & 0x1FFF) != 0) return;  // bỏ mảnh IP không phải mảnh đầu
        proto = data[at + 9];
        ip_payload = at + header;
        flow.assign(reinterpret_cast<const char *>(data + at + 12), 8);
    } else if (ether == kEtherIpv6) {
        if (at + 40 > length) return;
        proto = data[at + 6];
        ip_payload = at + 40;
        flow.assign(reinterpret_cast<const char *>(data + at + 8), 32);
    } else {
        return;
    }

    if (proto == kUdp) {
        if (ip_payload + 8 > length) return;
        uint16_t sport = be16(data + ip_payload), dport = be16(data + ip_payload + 2);
        const uint8_t *payload = data + ip_payload + 8;
        size_t size = length - ip_payload - 8;
        if (dport == 67) {
            on_dhcp(payload, size);
            return;
        }
        if ((src[0] & 1) != 0 || src == router_mac_) return;
        if (dport == 53) {
            on_dns(src, payload, size);
        } else if (dport == 5353 || sport == 5353) {
            on_mdns(src, payload, size);
        }
    } else if (proto == kTcp) {
        if ((src[0] & 1) != 0 || src == router_mac_) return;
        flow.append(reinterpret_cast<const char *>(data + ip_payload), 4);
        on_tcp(src, flow, data + ip_payload, length - ip_payload, seconds);
    }
}

void FeatureExtractor::on_dhcp(const uint8_t *data, size_t length) {
    constexpr size_t kOptions = 240;
    if (length < kOptions || data[0] != 1 || data[2] != 6 || be32(data + 236) != 0x63825363) return;
    Mac client;
    std::memcpy(client.data(), data + 28, 6);
    if ((client[0] & 1) != 0 || client == router_mac_) return;

    std::string prl, vci, hostname;
    uint8_t message = 0;
    size_t at = kOptions;
    while (at < length) {
        uint8_t code = data[at];
        if (code == 255) break;
        if (code == 0) {
            ++at;
            continue;
        }
        if (at + 2 > length || at + 2 + data[at + 1] > length) break;
        uint8_t size = data[at + 1];
        const uint8_t *value = data + at + 2;
        if (code == 53 && size == 1) {
            message = value[0];
        } else if (code == 55) {
            std::vector<uint32_t> items(value, value + size);
            prl = join_numbers(items);
        } else if (code == 60) {
            vci.assign(reinterpret_cast<const char *>(value), size);
        } else if (code == 12) {
            hostname.assign(reinterpret_cast<const char *>(value), size);
        }
        at += 2 + size;
    }

    if (trigger_ && devices_.find(client) == devices_.end()) {
        // Gia hạn lease có ciaddr khác 0: thiết bị đã kết nối từ trước, không phải join.
        const bool join = message == kDhcpDiscover || (message == kDhcpRequest && be32(data + 12) == 0);
        auto finished = finished_at_.find(client);
        const bool cooling = finished != finished_at_.end() && now_ - finished->second < cooldown_;
        if (!join || cooling) return;
        devices_[client].start = now_;
    }

    DeviceWindow &device = devices_[client];
    ++device.packets;
    ++device.dhcp;
    if (!prl.empty()) device.prl.add(prl);
    device.vci.add(sanitize_utf8(vci));
    device.hostname.add(sanitize_utf8(hostname));
}

void FeatureExtractor::on_dns(const Mac &src, const uint8_t *data, size_t length) {
    if (length < 12 || (data[2] & 0x80) != 0) return;  // chỉ lấy truy vấn
    uint16_t questions = be16(data + 4);
    size_t at = 12;
    DeviceWindow *found = session(src);
    if (found == nullptr) return;
    DeviceWindow &device = *found;
    ++device.packets;
    ++device.dns_queries;
    std::string name;
    for (uint16_t i = 0; i < questions; ++i) {
        if (!read_name(data, length, at, name) || at + 4 > length) return;
        at += 4;
        device.dns.add_name(sanitize_utf8(name));
    }
}

void FeatureExtractor::mdns_entry(DeviceWindow &device, int section, const std::string &name,
                                  const std::string &value) {
    if (device.mi_model.empty()) {
        std::string found;
        if (name.find("_mi-connect") != std::string::npos && re2::RE2::FullMatch(name, mi_re_, &found))
            device.mi_model = normalize_hostname(found);
    }
    if (section == kQuestion || value.empty()) return;
    if (device.model.empty()) {
        std::string found;
        if (re2::RE2::PartialMatch(value, model_re_, &found)) {
            size_t begin = found.find_first_not_of(" .");
            size_t end = found.find_last_not_of(" .");
            if (begin != std::string::npos) device.model = found.substr(begin, end - begin + 1);
        }
    }
    if (device.cast_model.empty() && lower_ascii(name).find("._googlecast._tcp") != std::string::npos) {
        std::string found;
        if (re2::RE2::PartialMatch(value, cast_re_, &found)) device.cast_model = normalize_hostname(found);
    }
}

void FeatureExtractor::on_mdns(const Mac &src, const uint8_t *data, size_t length) {
    if (length < 12) return;
    std::array<uint16_t, 4> counts = {be16(data + 4), be16(data + 6), be16(data + 8), be16(data + 10)};
    size_t at = 12;
    DeviceWindow *found = session(src);
    if (found == nullptr) return;
    DeviceWindow &device = *found;
    ++device.packets;
    ++device.mdns_packets;
    std::string name;
    for (uint16_t i = 0; i < counts[0]; ++i) {
        if (!read_name(data, length, at, name) || at + 4 > length) return;
        at += 4;
        std::string clean = sanitize_utf8(name);
        device.mdns.add_name(clean);
        mdns_entry(device, kQuestion, clean, "");
    }
    for (int section = 1; section <= 3; ++section) {
        for (uint16_t i = 0; i < counts[section]; ++i) {
            if (!read_name(data, length, at, name) || at + 10 > length) return;
            uint16_t type = be16(data + at);
            size_t rdlength = be16(data + at + 8);
            at += 10;
            if (at + rdlength > length) return;
            std::string value;
            if (type == kTypeTxt) value = sanitize_utf8(txt_value(data + at, rdlength));
            mdns_entry(device, section, sanitize_utf8(name), value);
            at += rdlength;
        }
    }
}

void FeatureExtractor::prune(uint32_t seconds) {
    for (auto it = pending_.begin(); it != pending_.end();) {
        if (seconds - it->second.seconds > kHelloTimeout)
            it = pending_.erase(it);
        else
            ++it;
    }
}

void FeatureExtractor::on_tcp(const Mac &src, const std::string &flow, const uint8_t *tcp, size_t length,
                              uint32_t seconds) {
    if (length < 20) return;
    if (trigger_ && devices_.find(src) == devices_.end()) return;
    size_t header = static_cast<size_t>(tcp[12] >> 4) * 4;
    if (header < 20 || header >= length) return;
    uint32_t seq = be32(tcp + 4);
    const uint8_t *payload = tcp + header;
    size_t size = length - header;

    if (size >= 6 && payload[0] == 0x16 && payload[1] == 0x03 && payload[5] == 0x01) {
        size_t needed = 5 + static_cast<size_t>(be16(payload + 3));
        if (needed > kMaxHello) return;
        if (size >= needed) {
            pending_.erase(flow);
            on_client_hello(src, payload, needed);
            return;
        }
        if (pending_.size() >= kMaxPending) prune(seconds);
        if (pending_.size() >= kMaxPending) pending_.clear();
        PendingHello &hello = pending_[flow];
        hello.data.assign(reinterpret_cast<const char *>(payload), size);
        hello.next_seq = seq + static_cast<uint32_t>(size);
        hello.seconds = seconds;
        hello.needed = needed;
        return;
    }

    if (pending_.empty()) return;
    auto found = pending_.find(flow);
    if (found == pending_.end()) return;
    PendingHello &hello = found->second;
    if (seq != hello.next_seq || seconds - hello.seconds > kHelloTimeout) return;
    hello.data.append(reinterpret_cast<const char *>(payload), size);
    hello.next_seq += static_cast<uint32_t>(size);
    if (hello.data.size() >= hello.needed) {
        std::string complete = std::move(hello.data);
        size_t needed = hello.needed;
        pending_.erase(found);
        on_client_hello(src, reinterpret_cast<const uint8_t *>(complete.data()), needed);
    }
}

void FeatureExtractor::on_client_hello(const Mac &src, const uint8_t *data, size_t length) {
    // TLS record (5) + handshake header (4) + version (2) + random (32)
    size_t at = 9;
    if (length < at + 35) return;
    char version[5];
    std::snprintf(version, sizeof version, "%02x%02x", data[at], data[at + 1]);
    at += 34;
    at += 1 + static_cast<size_t>(data[at]);  // session id
    if (at + 2 > length) return;
    size_t cipher_bytes = be16(data + at);
    at += 2;
    if (at + cipher_bytes > length) return;
    std::vector<uint32_t> ciphers;
    for (size_t i = 0; i + 1 < cipher_bytes; i += 2) {
        uint16_t cipher = be16(data + at + i);
        if (!is_grease(cipher)) ciphers.push_back(cipher);
    }
    at += cipher_bytes;
    if (at >= length) return;
    at += 1 + static_cast<size_t>(data[at]);  // compression

    std::vector<std::string> names, protocols;
    if (at + 2 <= length) {
        size_t end = std::min(length, at + 2 + static_cast<size_t>(be16(data + at)));
        at += 2;
        while (at + 4 <= end) {
            uint16_t type = be16(data + at);
            size_t size = be16(data + at + 2);
            size_t body = at + 4;
            if (body + size > end) break;
            if (type == 0 && size >= 2) {  // server_name
                size_t item = body + 2;
                while (item + 3 <= body + size) {
                    uint8_t kind = data[item];
                    size_t bytes = be16(data + item + 1);
                    if (item + 3 + bytes > body + size) break;
                    if (kind == 0)
                        names.emplace_back(reinterpret_cast<const char *>(data + item + 3), bytes);
                    item += 3 + bytes;
                }
            } else if (type == 16 && size >= 2) {  // ALPN
                size_t item = body + 2;
                while (item < body + size) {
                    size_t bytes = data[item];
                    if (item + 1 + bytes > body + size) break;
                    protocols.emplace_back(reinterpret_cast<const char *>(data + item + 1), bytes);
                    item += 1 + bytes;
                }
            }
            at = body + size;
        }
    }

    std::string alpn;
    for (size_t i = 0; i < protocols.size(); ++i) {
        if (i) alpn += ',';
        alpn += protocols[i];
    }
    alpn = sanitize_utf8(alpn);
    std::string cipher_text = join_numbers(ciphers);

    DeviceWindow *found = session(src);
    if (found == nullptr) return;
    DeviceWindow &device = *found;
    ++device.packets;
    ++device.tls;
    device.version.add(version);
    device.ciphers.add(cipher_text);
    device.alpn.add(lower_ascii(alpn));
    if (!cipher_text.empty()) device.fingerprint.add(std::string(version) + "|" + cipher_text + "|" + alpn);
    for (const auto &name : names) device.sni.add_name(sanitize_utf8(name));
}

std::vector<std::string> feature_row(const Mac &mac, const DeviceWindow &device,
                                     const std::string &lease_hostname) {
    std::string host = device.hostname.best();
    if (host == kMissing) {
        std::string trimmed = normalize_hostname(lease_hostname);
        host = trimmed.empty() ? kMissing : lease_hostname;
    }
    std::string normalized = normalize_hostname(host);

    char oui[9];
    std::snprintf(oui, sizeof oui, "%02x:%02x:%02x", mac[0], mac[1], mac[2]);
    bool random_mac = (mac[0] & 0x02) != 0;

    std::string model = !device.model.empty()        ? device.model
                        : !device.cast_model.empty() ? device.cast_model
                        : !device.mi_model.empty()   ? device.mi_model
                                                     : std::string(kMissing);

    return {device.prl.best(),
            device.fingerprint.best(),
            device.version.best(),
            device.alpn.best(),
            device.ciphers.best(),
            device.vci.best(),
            device.dns.text(),
            device.mdns.text(),
            device.sni.text(),
            random_mac ? std::string(kMissing) : std::string(oui),
            normalized.empty() ? std::string(kMissing) : normalized,
            model};
}

}  // namespace sdc
