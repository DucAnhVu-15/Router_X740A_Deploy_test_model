// Nhánh hostname của sdc_os.onnx viết bằng C++, đặc tả từ attach_hostname() trong
// 02.SDC/Code/pipeline/hostname_support.py. Dữ liệu nạp từ sdc_hn.bin.
#pragma once

#include <re2/re2.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace sdc {

using Labels = std::array<std::string, 3>;  // make, type, model

class HostnameEngine {
public:
    ~HostnameEngine();

    // Ánh xạ file vào bộ nhớ và biên dịch regex. Lỗi thì ném std::runtime_error.
    void load(const std::string &path);

    // Trả sdc/hn/result cho một dòng, tương đương chạy If trên batch 1 dòng.
    Labels run(const std::string &hostname, const std::string &mdns_model, const std::string &mac_oui,
               const Labels &packet) const;

    size_t rule_count() const;

private:
    struct Rule {
        std::unique_ptr<re2::RE2> regex;
        std::string label;
    };

    struct Expert {
        std::vector<std::string> labels;
        size_t classes = 0;
        float threshold = 0;
        const float *scale = nullptr;
        const float *bias = nullptr;
        const int8_t *weight = nullptr;  // [feature, class]
    };

    struct Candidate {
        std::string label;
        bool accepted = false;
    };

    Candidate expert(size_t head, const std::vector<std::pair<uint32_t, float>> &x, bool valid,
                     const std::string &hostname) const;
    bool encode(const std::string &hostname, std::vector<std::pair<uint32_t, float>> &x,
                size_t &length) const;
    int label_index(size_t head, const std::string &label) const;

    void *map_ = nullptr;
    size_t map_size_ = 0;

    std::unique_ptr<re2::RE2> bad_;
    std::vector<std::pair<uint32_t, uint32_t>> alias_;
    uint64_t base_ = 0;
    const uint64_t *gram_keys_ = nullptr;
    const uint32_t *gram_values_ = nullptr;
    size_t gram_count_ = 0;
    const float *idf_ = nullptr;
    size_t features_ = 0;

    std::array<Expert, 3> experts_;
    std::array<std::vector<Rule>, 3> rules_;
    std::unordered_map<std::string, std::unique_ptr<re2::RE2>> evidence_;
    std::unordered_set<std::string> strong_mdns_, strong_oui_;

    std::array<std::vector<std::string>, 3> labels_;
    std::array<std::unordered_map<std::string, int>, 3> label_index_;
    const uint8_t *type_guard_ = nullptr, *mask_make_ = nullptr, *mask_type_ = nullptr;
    const uint16_t *implied_make_ = nullptr, *implied_type_ = nullptr;
    std::vector<std::pair<std::string, std::string>> type_refine_;
};

}  // namespace sdc
