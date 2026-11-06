// Chuỗi suy luận: sdc_packet.ort -> hostname C++ -> sdc_tail.ort.
#pragma once

#include <fcntl.h>
#include <onnxruntime_cxx_api.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include "hostname_engine.h"

namespace sdc {

constexpr size_t kColumns = 12, kMacOui = 9, kHostname = 10, kMdnsModel = 11;

class MappedFile {
public:
    explicit MappedFile(const std::string &path) {
        int fd = open(path.c_str(), O_RDONLY);
        if (fd < 0) throw std::runtime_error("không mở được " + path);
        struct stat st {};
        fstat(fd, &st);
        size_ = static_cast<size_t>(st.st_size);
        data_ = mmap(nullptr, size_, PROT_READ, MAP_SHARED, fd, 0);
        close(fd);
        if (data_ == MAP_FAILED) throw std::runtime_error("mmap thất bại: " + path);
    }
    void *data() const { return data_; }
    size_t size() const { return size_; }

private:
    void *data_ = nullptr;
    size_t size_ = 0;
};

inline Ort::SessionOptions session_options() {
    Ort::SessionOptions options;
    options.SetIntraOpNumThreads(1);
    options.SetInterOpNumThreads(1);
    options.DisableCpuMemArena();
    options.DisableMemPattern();
    options.AddConfigEntry("session.use_ort_model_bytes_directly", "1");
    options.AddConfigEntry("session.use_ort_model_bytes_for_initializers", "1");
    return options;
}

class Pipeline {
public:
    Pipeline(Ort::Env &env, const std::string &dir)
        : packet_file_(dir + "/sdc_packet.ort"),
          tail_file_(dir + "/sdc_tail.ort"),
          packet_(env, packet_file_.data(), packet_file_.size(), session_options()),
          tail_(env, tail_file_.data(), tail_file_.size(), session_options()) {
        hostname_.load(dir + "/sdc_hn.bin");
    }

    Labels packet(const std::vector<std::string> &row) {
        Ort::Value input = tensor(cells(row), {1, static_cast<int64_t>(kColumns)});
        const char *in[] = {"input"};
        const char *out[] = {"sdc/packet_output"};
        auto got = packet_.Run(Ort::RunOptions{nullptr}, in, &input, 1, out, 1);
        return labels(got[0]);
    }

    Labels hostname(const std::vector<std::string> &row, const Labels &base) const {
        return hostname_.run(row[kHostname], row[kMdnsModel], row[kMacOui], base);
    }

    Labels tail(const std::vector<std::string> &row, const Labels &host) {
        std::array<Ort::Value, 2> inputs = {
            tensor(cells(row), {1, static_cast<int64_t>(kColumns)}),
            tensor({host[0].c_str(), host[1].c_str(), host[2].c_str()}, {1, 3})};
        const char *in[] = {"input", "hn_result"};
        const char *out[] = {"output"};
        auto got = tail_.Run(Ort::RunOptions{nullptr}, in, inputs.data(), 2, out, 1);
        return labels(got[0]);
    }

    Labels predict(const std::vector<std::string> &row) {
        return tail(row, hostname(row, packet(row)));
    }

private:
    static std::vector<const char *> cells(const std::vector<std::string> &row) {
        std::vector<const char *> values;
        values.reserve(row.size());
        for (const auto &cell : row) values.push_back(cell.c_str());
        return values;
    }

    Ort::Value tensor(const std::vector<const char *> &values, std::array<int64_t, 2> shape) {
        Ort::Value value = Ort::Value::CreateTensor(allocator_, shape.data(), shape.size(),
                                                    ONNX_TENSOR_ELEMENT_DATA_TYPE_STRING);
        value.FillStringTensor(values.data(), values.size());
        return value;
    }

    static Labels labels(const Ort::Value &value) {
        return {value.GetStringTensorElement(0), value.GetStringTensorElement(1),
                value.GetStringTensorElement(2)};
    }

    MappedFile packet_file_, tail_file_;
    Ort::Session packet_, tail_;
    HostnameEngine hostname_;
    Ort::AllocatorWithDefaultOptions allocator_;
};

}  // namespace sdc
