// Đọc pcap từ stdin (tcpdump -U -w -), gom feature theo MAC, chạy model, in JSON mỗi dòng.
// Mặc định gom theo cửa sổ cố định. Với --trigger-dhcp, mỗi thiết bị join mở một phiên; phiên kết thúc
// khi đủ DHCP + DNS + mDNS + TLS hoặc hết --timeout giây kể từ gói DHCP.
// Cách dùng: tcpdump ... -w - | sdc_agent <thư mục model> [--window 300] [--trigger-dhcp] [--timeout 300]
//                               [--output file] [--leases /tmp/dhcp.leases] [--router-mac aa:bb:..] [--columns]
#include <poll.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "feature_extract.h"
#include "pipeline.h"

namespace {

constexpr uint32_t kMagicMicro = 0xa1b2c3d4, kMagicNano = 0xa1b23c4d;
constexpr uint32_t kLinkEthernet = 1;
constexpr size_t kMaxFrame = 262144;
constexpr uint32_t kUnset = 0;
constexpr uint32_t kCooldownSeconds = 60;  // bỏ qua join lặp ngay sau khi vừa xong một phiên
constexpr int kPollMilliseconds = 1000;

uint32_t swap32(uint32_t v) {
    return (v >> 24) | ((v >> 8) & 0xFF00) | ((v << 8) & 0xFF0000) | (v << 24);
}

struct Options {
    std::string model_dir;
    std::string output;
    std::string leases = "/tmp/dhcp.leases";
    std::string router_mac;
    uint32_t window = 300;
    uint32_t timeout = 300;
    bool trigger = false;
    bool columns = false;
};

// Đọc stdin theo khối và gọi on_idle mỗi giây khi không có gói, để timeout vẫn chạy lúc mạng im lặng.
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
    std::vector<uint8_t> buffer_ = std::vector<uint8_t>(65536);
    size_t begin_ = 0, end_ = 0;
};

std::string json_escape(const std::string &text) {
    std::string out;
    out.reserve(text.size() + 8);
    for (char c : text) {
        if (c == '"' || c == '\\') {
            out += '\\';
            out += c;
        } else if (static_cast<unsigned char>(c) < 0x20) {
            char code[7];
            std::snprintf(code, sizeof code, "\\u%04x", c);
            out += code;
        } else {
            out += c;
        }
    }
    return out;
}

bool parse_mac(const std::string &text, sdc::Mac &mac) {
    unsigned v[6];
    if (std::sscanf(text.c_str(), "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6) return false;
    for (int i = 0; i < 6; ++i) mac[i] = static_cast<uint8_t>(v[i]);
    return true;
}

// dnsmasq: <hết hạn> <mac> <ip> <hostname> <client-id>; hostname `*` là không có tên.
std::map<std::string, std::string> read_leases(const std::string &path) {
    std::map<std::string, std::string> names;
    std::ifstream file(path);
    std::string line;
    while (std::getline(file, line)) {
        std::istringstream fields(line);
        std::string expiry, mac, ip, name;
        if ((fields >> expiry >> mac >> ip >> name) && name != "*") names[mac] = name;
    }
    return names;
}

std::string iso_time(uint32_t seconds) {
    std::time_t value = seconds;
    std::tm parts{};
    gmtime_r(&value, &parts);
    char text[32];
    std::strftime(text, sizeof text, "%Y-%m-%dT%H:%M:%SZ", &parts);
    return text;
}

std::string sources(const sdc::DeviceWindow &device) {
    std::string out;
    auto add = [&out](const char *name, uint32_t count) {
        if (!count) return;
        if (!out.empty()) out += '+';
        out += name;
    };
    add("dhcp", device.dhcp);
    add("dns", device.dns_queries);
    add("mdns", device.mdns_packets);
    add("tls", device.tls);
    return out;
}

const char *const kColumnNames[sdc::kColumns] = {
    "dhcp_prl", "tls_fp", "tls_version", "tls_alpn", "tls_ciphers", "dhcp_vci",
    "dns_tokens", "mdns_tokens", "tls_sni_tokens", "mac_oui", "dhcp_hostname", "mdns_model"};

class Reporter {
public:
    Reporter(sdc::Pipeline &pipeline, const Options &options) : pipeline_(pipeline), options_(options) {
        if (!options.output.empty()) file_.open(options.output, std::ios::app);
    }

    void flush(std::map<sdc::Mac, sdc::DeviceWindow> window, uint32_t start) {
        auto leases = read_leases(options_.leases);
        for (const auto &[mac, device] : window) report(mac, device, leases, start, "window", 0);
    }

    void flush(const std::vector<sdc::FinishedSession> &sessions) {
        if (sessions.empty()) return;
        auto leases = read_leases(options_.leases);
        for (const auto &item : sessions)
            report(item.mac, item.device, leases, item.device.start, item.reason, item.seconds - item.device.start);
    }

private:
    void report(const sdc::Mac &mac, const sdc::DeviceWindow &device,
                const std::map<std::string, std::string> &leases, uint32_t start, const char *reason,
                uint32_t elapsed) {
        const std::string text = sdc::mac_text(mac);
        auto lease = leases.find(text);
        auto row = sdc::feature_row(mac, device, lease == leases.end() ? "" : lease->second);
        try {
            auto start_time = std::chrono::steady_clock::now();
            sdc::Labels labels = pipeline_.predict(row);
            double ms = std::chrono::duration<double, std::milli>(
                            std::chrono::steady_clock::now() - start_time).count();
            write(text, device, row, labels, start, reason, elapsed, ms);
        } catch (const std::exception &error) {
            std::cerr << "LOI suy luan " << text << ": " << error.what() << "\n";
        }
    }

    void write(const std::string &mac, const sdc::DeviceWindow &device, const std::vector<std::string> &row,
               const sdc::Labels &labels, uint32_t start, const char *reason, uint32_t elapsed, double ms) {
        std::ostringstream out;
        out << "{\"window_start\":\"" << iso_time(start) << "\",\"mac\":\"" << mac << "\",\"make\":\""
            << json_escape(labels[0]) << "\",\"type\":\"" << json_escape(labels[1]) << "\",\"model\":\""
            << json_escape(labels[2]) << "\",\"hostname\":\"" << json_escape(row[sdc::kHostname])
            << "\",\"reason\":\"" << reason << "\",\"elapsed_s\":" << elapsed << ",\"sources\":\"" << sources(device)
            << "\",\"packets\":" << device.packets << ",\"infer_ms\":" << ms;
        if (options_.columns) {
            out << ",\"columns\":{";
            for (size_t i = 0; i < sdc::kColumns; ++i)
                out << (i ? "," : "") << "\"" << kColumnNames[i] << "\":\"" << json_escape(row[i]) << "\"";
            out << "}";
        }
        out << "}\n";
        std::cout << out.str() << std::flush;
        if (file_) file_ << out.str() << std::flush;
    }

    sdc::Pipeline &pipeline_;
    const Options &options_;
    std::ofstream file_;
};

int run(const Options &options) {
    Input input;
    auto no_idle = [] {};
    uint32_t header[6];
    if (!input.read(header, sizeof header, no_idle)) {
        std::cerr << "khong doc duoc pcap header tu stdin\n";
        return 1;
    }
    bool swapped = header[0] == swap32(kMagicMicro) || header[0] == swap32(kMagicNano);
    uint32_t magic = swapped ? swap32(header[0]) : header[0];
    uint32_t link = swapped ? swap32(header[5]) : header[5];
    if ((magic != kMagicMicro && magic != kMagicNano) || (link & 0xFFFF) != kLinkEthernet) {
        std::cerr << "chi ho tro pcap Ethernet, link=" << link << "\n";
        return 1;
    }

    Ort::Env env(ORT_LOGGING_LEVEL_ERROR, "sdc");
    auto load_start = std::chrono::steady_clock::now();
    sdc::Pipeline pipeline(env, options.model_dir);
    std::cerr << "model loaded in "
              << std::chrono::duration<double>(std::chrono::steady_clock::now() - load_start).count() << "s\n";

    sdc::FeatureExtractor extractor;
    sdc::Mac router{};
    if (!options.router_mac.empty() && parse_mac(options.router_mac, router)) extractor.set_router_mac(router);
    if (options.trigger) extractor.enable_trigger(options.timeout, kCooldownSeconds);

    Reporter reporter(pipeline, options);
    std::vector<uint8_t> frame(kMaxFrame);
    uint32_t window_start = kUnset, last_seconds = kUnset;
    std::time_t last_wall = 0;

    // Đồng hồ theo gói, cộng thêm thời gian thực đã trôi từ gói cuối khi mạng im lặng.
    auto on_idle = [&] {
        if (options.trigger && last_seconds != kUnset)
            reporter.flush(extractor.take_finished(
                last_seconds + static_cast<uint32_t>(std::time(nullptr) - last_wall)));
    };

    uint32_t record[4];
    while (input.read(record, sizeof record, on_idle)) {
        uint32_t seconds = swapped ? swap32(record[0]) : record[0];
        uint32_t captured = swapped ? swap32(record[2]) : record[2];
        if (captured > kMaxFrame) {
            std::cerr << "pcap hong: captured=" << captured << "\n";
            return 1;
        }
        if (!input.read(frame.data(), captured, on_idle)) break;
        last_seconds = seconds;
        last_wall = std::time(nullptr);

        if (options.trigger) {
            reporter.flush(extractor.take_finished(seconds));  // phiên hết giờ không nhận gói đến muộn
            extractor.add_frame(frame.data(), captured, seconds);
            reporter.flush(extractor.take_finished(seconds));
            continue;
        }
        if (window_start == kUnset) window_start = seconds;
        if (seconds - window_start >= options.window) {
            reporter.flush(extractor.take_window(), window_start);
            window_start = seconds;
        }
        extractor.add_frame(frame.data(), captured, seconds);
    }
    if (options.trigger)
        reporter.flush(extractor.take_finished(last_seconds, true));
    else
        reporter.flush(extractor.take_window(), window_start);
    std::cerr << "frames=" << extractor.frames() << "\n";
    return 0;
}

}  // namespace

int main(int argc, char **argv) {
    if (argc < 2) {
        std::cerr << "usage: sdc_agent <model_dir> [--window 300] [--trigger-dhcp] [--timeout 300] "
                     "[--output file] [--leases path] [--router-mac mac] [--columns]\n";
        return 2;
    }
    Options options;
    options.model_dir = argv[1];
    for (int i = 2; i < argc; ++i) {
        std::string key = argv[i];
        auto next = [&]() -> std::string {
            if (i + 1 >= argc) throw std::runtime_error("thieu gia tri cho " + key);
            return argv[++i];
        };
        try {
            if (key == "--window") {
                options.window = static_cast<uint32_t>(std::strtoul(next().c_str(), nullptr, 10));
            } else if (key == "--trigger-dhcp") {
                options.trigger = true;
            } else if (key == "--timeout") {
                options.timeout = static_cast<uint32_t>(std::strtoul(next().c_str(), nullptr, 10));
            } else if (key == "--output") {
                options.output = next();
            } else if (key == "--leases") {
                options.leases = next();
            } else if (key == "--router-mac") {
                options.router_mac = next();
            } else if (key == "--columns") {
                options.columns = true;
            } else {
                std::cerr << "tham so la: " << key << "\n";
                return 2;
            }
        } catch (const std::exception &error) {
            std::cerr << error.what() << "\n";
            return 2;
        }
    }
    if (options.window == 0) options.window = 300;
    try {
        return run(options);
    } catch (const std::exception &error) {
        std::cerr << "LOI: " << error.what() << "\n";
        return 1;
    }
}
