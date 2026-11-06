// Trích feature từ gói tin thô, gom theo MAC, xuất 12 cột theo FEATURES.md.
// Logic gộp cửa sổ khớp feature_row() trong test_release_observations.py.
#pragma once

#include <re2/re2.h>

#include <array>
#include <cstdint>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

namespace sdc {

using Mac = std::array<uint8_t, 6>;

std::string mac_text(const Mac &mac);
std::string normalize_hostname(const std::string &value);
std::string sanitize_utf8(const std::string &value);

// Đếm giá trị trong cửa sổ, hoà thì lấy giá trị nhỏ nhất theo thứ tự chuỗi.
class ModeCounter {
public:
    void add(const std::string &value);
    std::string best() const;

private:
    std::map<std::string, uint32_t> counts_;
};

// Token duy nhất theo thứ tự gặp, tối đa 40 token.
class TokenSet {
public:
    void add_name(const std::string &name);
    std::string text() const;
    bool empty() const { return tokens_.empty(); }

private:
    std::vector<std::string> tokens_;
};

struct DeviceWindow {
    ModeCounter prl, vci, hostname, fingerprint, version, alpn, ciphers;
    TokenSet dns, mdns, sni;
    std::string model, cast_model, mi_model;
    uint32_t packets = 0, dhcp = 0, dns_queries = 0, mdns_packets = 0, tls = 0;
    uint32_t start = 0;  // thời điểm gói DHCP mở phiên

    bool all_sources() const { return dhcp && dns_queries && mdns_packets && tls; }
};

struct FinishedSession {
    Mac mac;
    DeviceWindow device;
    const char *reason;
    uint32_t seconds;  // thời điểm kết thúc phiên
};

class FeatureExtractor {
public:
    FeatureExtractor();

    void set_router_mac(const Mac &mac) { router_mac_ = mac; }

    // Bật chế độ phiên: chỉ thiết bị vừa join qua DHCP mới được gom dữ liệu.
    void enable_trigger(uint32_t timeout, uint32_t cooldown);

    // data là khung Ethernet đã bắt; length là số byte có trong data.
    void add_frame(const uint8_t *data, size_t length, uint32_t seconds);

    // Lấy và xoá dữ liệu cửa sổ hiện tại.
    std::map<Mac, DeviceWindow> take_window();

    // Lấy các phiên đã đủ 4 nguồn hoặc hết giờ. final = true lấy cả phiên còn dang dở.
    std::vector<FinishedSession> take_finished(uint32_t now, bool final = false);

    size_t frames() const { return frames_; }

private:
    struct PendingHello {
        std::string data;
        uint32_t next_seq = 0;
        uint32_t seconds = 0;
        size_t needed = 0;
    };

    void on_dhcp(const uint8_t *data, size_t length);
    void on_dns(const Mac &src, const uint8_t *data, size_t length);
    void on_mdns(const Mac &src, const uint8_t *data, size_t length);
    void on_tcp(const Mac &src, const std::string &flow, const uint8_t *tcp, size_t length, uint32_t seconds);
    void on_client_hello(const Mac &src, const uint8_t *data, size_t length);
    void mdns_entry(DeviceWindow &device, int section, const std::string &name, const std::string &value);
    void prune(uint32_t seconds);
    DeviceWindow *session(const Mac &mac);

    std::map<Mac, DeviceWindow> devices_;
    std::map<Mac, uint32_t> finished_at_;
    std::unordered_map<std::string, PendingHello> pending_;
    Mac router_mac_{};
    bool trigger_ = false;
    uint32_t timeout_ = 300, cooldown_ = 0, now_ = 0;
    re2::RE2 model_re_, cast_re_, mi_re_;
    size_t frames_ = 0;
};

// 12 cột đúng thứ tự contract. lease_hostname dùng khi cửa sổ không có DHCP option 12.
std::vector<std::string> feature_row(const Mac &mac, const DeviceWindow &device,
                                     const std::string &lease_hostname);

}  // namespace sdc
