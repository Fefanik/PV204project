// src/verify_cli.cpp
#include <iostream>
#include <vector>
#include <string>
#include <cstdint>

#include "frost_ffi.h"
#include "base64.h"

int main(int argc, char** argv) {
    if (argc != 4) {
        std::cerr << "Usage:\n  verify_cli <payload_signed> <final_signature_b64> <public_key_b64>\n";
        return 2;
    }
    const std::string payload = argv[1];
    std::string sig_b64 = argv[2];
    std::string pub_b64 = argv[3];

    auto sig = b64dec(sig_b64);
    if (sig.size() != 64) {
        std::cerr << "Bad sig len: " << sig.size() << " (expected 64)\n";
        return 1;
    }

    auto pub_pkg = b64dec(pub_b64);
    if (pub_pkg.empty()) {
        std::cerr << "Bad public key string or empty base64.\n";
        return 1;
    }

    int rc = frost_verify(
        reinterpret_cast<const uint8_t*>(payload.data()),
        payload.size(),
        sig.data(),
        sig.size(),
        pub_pkg.data(),
        pub_pkg.size()
    );

    std::cout << (rc == 0 ? "VALID\n" : "INVALID\n");
    return rc;
}