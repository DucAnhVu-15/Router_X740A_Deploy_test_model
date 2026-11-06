// Đo RAM và thời gian của sdc_os.onnx bằng ONNX Runtime C++ (không có Python).
// Cách dùng: mem_probe <model.onnx> [all|basic|off]
#include <fcntl.h>
#include <onnxruntime_cxx_api.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

static long status_kb(const char *key) {
    std::ifstream f("/proc/self/status");
    std::string line;
    size_t n = std::strlen(key);
    while (std::getline(f, line))
        if (line.compare(0, n, key) == 0) return std::stol(line.substr(n + 1));
    return -1;
}

static void report(const char *stage) {
    std::printf("%-14s RSS=%6.1f MB  peak=%6.1f MB\n", stage, status_kb("VmRSS") / 1024.0,
                status_kb("VmHWM") / 1024.0);
    std::fflush(stdout);
}

static double seconds_since(std::chrono::steady_clock::time_point t) {
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - t).count();
}

int main(int argc, char **argv) {
    if (argc < 2) {
        std::cerr << "usage: mem_probe <model.onnx> [all|basic|off]\n";
        return 2;
    }
    const std::string level = argc > 2 ? argv[2] : "off";
    report("start");

    Ort::Env env(ORT_LOGGING_LEVEL_ERROR, "sdc");
    Ort::SessionOptions so;
    so.SetIntraOpNumThreads(1);
    so.SetInterOpNumThreads(1);
    so.DisableCpuMemArena();
    so.DisableMemPattern();
    so.SetGraphOptimizationLevel(level == "all"     ? GraphOptimizationLevel::ORT_ENABLE_ALL
                                 : level == "basic" ? GraphOptimizationLevel::ORT_ENABLE_BASIC
                                                    : GraphOptimizationLevel::ORT_DISABLE_ALL);

    // File .ort: ánh xạ vào bộ nhớ và cho runtime dùng trực tiếp thay vì sao chép.
    const std::string path = argv[1];
    const bool is_ort = path.size() > 4 && path.compare(path.size() - 4, 4, ".ort") == 0;
    void *mapped = nullptr;
    size_t mapped_size = 0;
    if (is_ort) {
        int fd = open(argv[1], O_RDONLY);
        struct stat st {};
        if (fd < 0 || fstat(fd, &st) != 0) {
            std::cerr << "cannot open model\n";
            return 2;
        }
        mapped_size = static_cast<size_t>(st.st_size);
        mapped = mmap(nullptr, mapped_size, PROT_READ, MAP_SHARED, fd, 0);
        close(fd);
        if (mapped == MAP_FAILED) {
            std::cerr << "mmap failed\n";
            return 2;
        }
        so.AddConfigEntry("session.use_ort_model_bytes_directly", "1");
        so.AddConfigEntry("session.use_ort_model_bytes_for_initializers", "1");
    }

    auto t = std::chrono::steady_clock::now();
    Ort::Session session = is_ort ? Ort::Session(env, mapped, mapped_size, so)
                                  : Ort::Session(env, argv[1], so);
    std::printf("load_seconds=%.2f\n", seconds_since(t));
    report("loaded");

    // Cùng một dòng thử với phép đo Python, thứ tự theo contract 12 cột.
    const std::array<const char *, 12> row = {
        "1,3,6,15,26,28,51,58,59,43,114,108", "<missing>", "<missing>", "<missing>", "<missing>",
        "android-dhcp-17", "google com youtube", "<missing>", "<missing>", "a2bc03",
        "S23-cua-Thang", "<missing>"};
    std::array<int64_t, 2> shape = {1, 12};
    Ort::AllocatorWithDefaultOptions alloc;
    Ort::Value input = Ort::Value::CreateTensor(alloc, shape.data(), shape.size(),
                                                ONNX_TENSOR_ELEMENT_DATA_TYPE_STRING);
    input.FillStringTensor(row.data(), row.size());

    const char *in_names[] = {"input"};
    const char *out_names[] = {"output"};
    std::vector<Ort::Value> out;
    double first = 0, last = 0;
    for (int i = 0; i < 20; ++i) {
        t = std::chrono::steady_clock::now();
        out = session.Run(Ort::RunOptions{nullptr}, in_names, &input, 1, out_names, 1);
        last = seconds_since(t);
        if (i == 0) first = last;
    }
    std::printf("infer_first_ms=%.1f infer_last_ms=%.1f\n", first * 1000, last * 1000);
    report("inferred");

    std::cout << "output=";
    for (size_t i = 0; i < 3; ++i) std::cout << out[0].GetStringTensorElement(i) << " | ";
    std::cout << "\n";
    return 0;
}
