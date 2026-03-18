#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include "frost_ffi.h"   // make sure this is in your include path

static void write_file(const std::string& path, const uint8_t* p, size_t n) {
    std::ofstream f(path, std::ios::binary);
    if (!f) { std::cerr << "ERROR: cannot open " << path << " for writing\n"; std::exit(2); }
    f.write(reinterpret_cast<const char*>(p), static_cast<std::streamsize>(n));
}

static void print_c_array(const char* symbol, const uint8_t* p, size_t n) {
    std::cout << "static const uint8_t " << symbol << "[] = {\n  ";
    for (size_t i = 0; i < n; ++i) {
        std::cout << "0x" << std::hex << std::uppercase
                  << std::setw(2) << std::setfill('0') << (int)p[i];
        if (i + 1 != n) std::cout << ", ";
        if ((i + 1) % 16 == 0 && i + 1 != n) std::cout << "\n  ";
    }
    std::cout << std::dec << "\n};\n";
    std::cout << "static const size_t " << symbol << "_LEN = sizeof(" << symbol << ");\n";
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr <<
        "Usage: keygen <n> <t> <out_dir> [--emit-c-array]\n"
        "Example:\n"
        "  keygen 3 2 ./keys --emit-c-array > pubpkg_array.inc\n";
        return 1;
    }

    const uint16_t n = static_cast<uint16_t>(std::stoi(argv[1]));
    const uint16_t t = static_cast<uint16_t>(std::stoi(argv[2]));
    const std::string out_dir = argv[3];
    const bool emit_c_array = (argc >= 5 && std::string(argv[4]) == "--emit-c-array");

    // Prepare arrays to receive pointers from Rust
    std::vector<uint8_t*> key_ptrs(n, nullptr);
    std::vector<size_t>   key_lens(n, 0);
    uint8_t* pub_ptr = nullptr;
    size_t   pub_len = 0;

    // Call Rust FROST keygen (trusted dealer)
    if (frost_keygen(n, t, key_ptrs.data(), key_lens.data(), &pub_ptr, &pub_len) != 0) {
        std::cerr << "ERROR: frost_keygen failed\n";
        return 2;
    }

    // Write per-node key files
    for (uint16_t i = 0; i < n; ++i) {
        if (!key_ptrs[i] || key_lens[i] == 0) {
            std::cerr << "ERROR: empty key for node " << (i+1) << "\n";
            return 3;
        }
        const std::string path = out_dir + "/node" + std::to_string(i+1) + ".key";
        write_file(path, key_ptrs[i], key_lens[i]);
        std::cout << "Wrote " << path << " (" << key_lens[i] << " bytes)\n";
    }

    // Write PublicKeyPackage to disk
    const std::string pub_path = out_dir + "/coord.key";
    write_file(pub_path, pub_ptr, pub_len);
    std::cout << "Wrote " << pub_path << " (" << pub_len << " bytes)\n";

    // Optionally print a C array you can paste into your server code
    if (emit_c_array) {
        print_c_array("HARDCODED_PUBKEY_PKG", pub_ptr, pub_len);
    }

    // Free Rust-allocated buffers
    if (pub_ptr) std::free(pub_ptr);
    for (auto* p : key_ptrs) if (p) std::free(p);

    return 0;
}
