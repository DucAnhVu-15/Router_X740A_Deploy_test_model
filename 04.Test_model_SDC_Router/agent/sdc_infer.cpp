// Chạy đủ chuỗi SDC: sdc_packet.ort -> hostname C++ -> sdc_tail.ort, rồi đối chiếu với model gốc.
// Cách dùng: sdc_infer <thư mục model> [parity_cases.txt] [số dòng tối đa]
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "pipeline.h"

namespace {

using sdc::kColumns;
using sdc::kHostname;
using sdc::Pipeline;
constexpr size_t kCaseFields = kColumns + 9;

using Clock = std::chrono::steady_clock;

double elapsed(Clock::time_point start) {
    return std::chrono::duration<double>(Clock::now() - start).count();
}

long status_kb(const char *key) {
    std::ifstream file("/proc/self/status");
    std::string line;
    size_t n = std::strlen(key);
    while (std::getline(file, line))
        if (line.compare(0, n, key) == 0) return std::stol(line.substr(n + 1));
    return -1;
}

void report(const char *stage) {
    std::printf("%-12s RSS=%6.1f MB  peak=%6.1f MB\n", stage, status_kb("VmRSS") / 1024.0,
                status_kb("VmHWM") / 1024.0);
    std::fflush(stdout);
}

std::vector<std::string> split(const std::string &line) {
    std::vector<std::string> fields;
    size_t start = 0, end;
    while ((end = line.find('\x1f', start)) != std::string::npos) {
        fields.push_back(line.substr(start, end - start));
        start = end + 1;
    }
    fields.push_back(line.substr(start));
    return fields;
}

std::string join(const sdc::Labels &labels) { return labels[0] + " | " + labels[1] + " | " + labels[2]; }

int run_cases(Pipeline &pipeline, const std::string &path, size_t limit) {
    std::ifstream file(path);
    if (!file) throw std::runtime_error("không mở được " + path);

    size_t rows = 0, wrong_packet = 0, wrong_host = 0, wrong_final = 0, shown = 0;
    double packet_seconds = 0, host_seconds = 0, tail_seconds = 0, worst = 0;
    std::string line;
    while (rows < limit && std::getline(file, line)) {
        auto fields = split(line);
        if (fields.size() != kCaseFields) throw std::runtime_error("sai số trường trong bộ test");
        std::vector<std::string> row(fields.begin(), fields.begin() + kColumns);
        auto expected = [&](size_t offset) {
            return sdc::Labels{fields[kColumns + offset], fields[kColumns + offset + 1],
                               fields[kColumns + offset + 2]};
        };

        auto start = Clock::now();
        sdc::Labels packet = pipeline.packet(row);
        double t1 = elapsed(start);
        start = Clock::now();
        sdc::Labels host = pipeline.hostname(row, expected(0));
        double t2 = elapsed(start);
        start = Clock::now();
        sdc::Labels final_labels = pipeline.tail(row, host);
        double t3 = elapsed(start);
        packet_seconds += t1;
        host_seconds += t2;
        tail_seconds += t3;
        worst = std::max(worst, t1 + t2 + t3);
        ++rows;

        bool packet_bad = packet != expected(0), host_bad = host != expected(3),
             final_bad = final_labels != expected(6);
        wrong_packet += packet_bad;
        wrong_host += host_bad;
        wrong_final += final_bad;
        if ((packet_bad || host_bad || final_bad) && shown < 12) {
            ++shown;
            std::cout << "LECH host=[" << row[kHostname] << "]\n";
            if (packet_bad) std::cout << "  packet " << join(packet) << "\n      vs " << join(expected(0)) << "\n";
            if (host_bad) std::cout << "  host   " << join(host) << "\n      vs " << join(expected(3)) << "\n";
            if (final_bad) std::cout << "  final  " << join(final_labels) << "\n      vs " << join(expected(6)) << "\n";
        }
    }
    std::printf("rows=%zu lech_packet=%zu lech_hostname=%zu lech_final=%zu\n", rows, wrong_packet, wrong_host,
                wrong_final);
    if (rows > 0) {
        std::printf("trung_binh_ms packet=%.2f hostname=%.2f tail=%.2f tong=%.2f cham_nhat=%.1f\n",
                    packet_seconds * 1000 / rows, host_seconds * 1000 / rows, tail_seconds * 1000 / rows,
                    (packet_seconds + host_seconds + tail_seconds) * 1000 / rows, worst * 1000);
    }
    return (wrong_packet + wrong_host + wrong_final) == 0 ? 0 : 1;
}

}  // namespace

int main(int argc, char **argv) {
    if (argc < 2) {
        std::cerr << "usage: sdc_infer <model_dir> [parity_cases.txt] [max_rows]\n";
        return 2;
    }
    try {
        report("start");
        Ort::Env env(ORT_LOGGING_LEVEL_ERROR, "sdc");
        auto start = Clock::now();
        Pipeline pipeline(env, argv[1]);
        std::printf("load_seconds=%.2f\n", elapsed(start));
        report("loaded");

        const std::vector<std::string> sample = {
            "1,3,6,15,26,28,51,58,59,43,114,108", "<missing>", "<missing>", "<missing>", "<missing>",
            "android-dhcp-17", "google com youtube", "<missing>", "<missing>", "a2bc03",
            "s23-cua-thang", "<missing>"};
        sdc::Labels base = pipeline.packet(sample);
        sdc::Labels host = pipeline.hostname(sample, base);
        std::cout << "sample=" << join(pipeline.tail(sample, host)) << "\n";
        report("sample");

        int status = 0;
        if (argc > 2) {
            size_t limit = argc > 3 ? std::strtoull(argv[3], nullptr, 10) : static_cast<size_t>(-1);
            status = run_cases(pipeline, argv[2], limit);
            report("cases");
        }
        return status;
    } catch (const std::exception &error) {
        std::cerr << "LOI: " << error.what() << "\n";
        return 1;
    }
}
