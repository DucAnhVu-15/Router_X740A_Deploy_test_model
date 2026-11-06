// Kiểm tra toolchain: dùng các phần C++ mà ONNX Runtime cần (thread, exception, STL).
#include <sys/utsname.h>

#include <atomic>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

int main() {
    struct utsname u {};
    uname(&u);

    std::atomic<int> sum{0};
    std::vector<std::thread> workers;
    for (int i = 1; i <= 4; ++i) workers.emplace_back([&sum, i] { sum += i; });
    for (auto &t : workers) t.join();

    std::string caught;
    try {
        throw std::runtime_error("ok");
    } catch (const std::exception &e) {
        caught = e.what();
    }

    std::cout << "Hello from SDC toolchain\n"
              << "kernel_arch=" << u.machine << " kernel=" << u.release << "\n"
              << "pointer_bits=" << sizeof(void *) * 8 << "\n"
              << "hw_threads=" << std::thread::hardware_concurrency() << "\n"
              << "thread_test=" << (sum == 10 ? "ok" : "FAIL") << "\n"
              << "exception_test=" << caught << "\n";
    return (sum == 10 && caught == "ok") ? 0 : 1;
}
