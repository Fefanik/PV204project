#include "keygen.hpp"
#include "frost_ffi.h"

#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <cstdlib>
#include <utility>

namespace {

    struct FrostKeyPackage {
        std::vector<uint8_t*> node_keys;
        std::vector<size_t> node_lens;
        uint8_t* pub_ptr = nullptr;
        size_t pub_len = 0;

        explicit FrostKeyPackage(uint16_t n) : node_keys(n, nullptr), node_lens(n, 0) {}

        ~FrostKeyPackage() {
            if (pub_ptr) std::free(pub_ptr);
            for (auto* p : node_keys) {
                if (p) std::free(p);
            }
        }

        FrostKeyPackage(const FrostKeyPackage&) = delete;
        FrostKeyPackage& operator=(const FrostKeyPackage&) = delete;

        FrostKeyPackage(FrostKeyPackage&& other) noexcept
            : node_keys(std::move(other.node_keys)),
              node_lens(std::move(other.node_lens)),
              pub_ptr(other.pub_ptr),
              pub_len(other.pub_len) {
            // Null out the source object's pointers so its destructor does nothing
            other.pub_ptr = nullptr;
            other.node_keys.assign(other.node_keys.size(), nullptr);
        }

        FrostKeyPackage& operator=(FrostKeyPackage&& other) noexcept {
            if (this != &other) {
                // Free existing resources
                if (pub_ptr) std::free(pub_ptr);
                for (auto* p : node_keys) if (p) std::free(p);

                // Pilfer resources from other
                node_keys = std::move(other.node_keys);
                node_lens = std::move(other.node_lens);
                pub_ptr = other.pub_ptr;
                pub_len = other.pub_len;

                // Null out the source object's pointers
                other.pub_ptr = nullptr;
                other.node_keys.assign(other.node_keys.size(), nullptr);
            }
            return *this;
        }
    };

    void write_file(const std::string& path, const uint8_t* data, size_t size) {
        std::ofstream f(path, std::ios::binary);
        if (!f) throw std::runtime_error("Cannot open " + path + " for writing");
        f.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(size));
    }

    void print_c_array(const std::string& symbol, const uint8_t* data, size_t size) {
        std::cout << "static const uint8_t " << symbol << "[] = {\n  ";
        for (size_t i = 0; i < size; ++i) {
            std::cout << "0x" << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
            if (i + 1 != size) std::cout << ", ";
            if ((i + 1) % 16 == 0 && i + 1 != size) std::cout << "\n  ";
        }
        std::cout << std::dec << "\n};\n";
        std::cout << "static const size_t " << symbol << "_LEN = sizeof(" << symbol << ");\n";
    }

    FrostKeyPackage generate_keys(uint16_t n, uint16_t t) {
        FrostKeyPackage keys(n);
        if (frost_keygen(n, t, keys.node_keys.data(), keys.node_lens.data(), &keys.pub_ptr, &keys.pub_len) != 0) {
            throw std::runtime_error("frost_keygen failed inside FFI");
        }
        return keys;
    }

    void save_node_keys(const KeygenConfig& config, const FrostKeyPackage& keys) {
        for (uint16_t i = 0; i < config.n; ++i) {
            if (!keys.node_keys[i] || keys.node_lens[i] == 0) {
                throw std::runtime_error("Empty key received from FFI for node " + std::to_string(i + 1));
            }
            const std::string path = config.out_dir + "/node" + std::to_string(i + 1) + ".key";
            write_file(path, keys.node_keys[i], keys.node_lens[i]);
            std::cout << "Wrote " << path << " (" << keys.node_lens[i] << " bytes)\n";
        }
    }

    void save_coordinator_key(const KeygenConfig& config, const FrostKeyPackage& keys) {
        const std::string pub_path = config.out_dir + "/coord.key";
        write_file(pub_path, keys.pub_ptr, keys.pub_len);
        std::cout << "Wrote " << pub_path << " (" << keys.pub_len << " bytes)\n";
    }

} // anonymous namespace

KeygenConfig parse_arguments(int argc, char* argv[]) {
    if (argc < 4) {
        throw std::invalid_argument(
            "Usage: keygen <n> <t> <out_dir> [--emit-c-array]\n"
            "Example:\n  keygen 3 2 ./keys --emit-c-array > pubpkg_array.inc"
        );
    }
    KeygenConfig config;
    config.n = static_cast<uint16_t>(std::stoi(argv[1]));
    config.t = static_cast<uint16_t>(std::stoi(argv[2]));
    config.out_dir = argv[3];
    config.emit_c_array = (argc >= 5 && std::string(argv[4]) == "--emit-c-array");
    return config;
}

void run_keygen(const KeygenConfig& config) {
    FrostKeyPackage keys = generate_keys(config.n, config.t);
    save_node_keys(config, keys);
    save_coordinator_key(config, keys);
}