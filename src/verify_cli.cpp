// src/verify_cli.cpp
#include <iostream>
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <algorithm>

#include "frost_ffi.h"

static inline int b64val(int c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1; 
}

static std::vector<uint8_t> b64dec(std::string s) {
    s.erase(std::remove_if(s.begin(), s.end(),[](unsigned char ch){
        return ch=='\n' || ch=='\r' || ch=='\t' || ch==' ';
    }), s.end());

    std::vector<uint8_t> out;
    out.reserve(s.size() * 3 / 4);

    int q[4]; int qi = 0; int pad = 0;

    auto flush = [&](int valid){
        if (valid < 2) return;
        int v0 = q[0], v1 = q[1], v2 = (valid > 2 ? q[2] : 0), v3 = (valid > 3 ? q[3] : 0);
        uint32_t triple = (uint32_t(v0) << 18) | (uint32_t(v1) << 12) |
                          (uint32_t(v2) <<  6) |  uint32_t(v3);
        out.push_back((triple >> 16) & 0xFF);
        if (valid > 2) out.push_back((triple >> 8) & 0xFF);
        if (valid > 3) out.push_back(triple & 0xFF);
    };

    for (unsigned char ch : s) {
        if (ch == '=') {
            q[qi++] = 0;
            pad++;
            if (qi == 4) {
                int valid = 4 - pad; 
                flush(valid);
                qi = 0;
                pad = 0;
            }
            continue;
        }
        int v = b64val(ch);
        if (v < 0) continue; 
        q[qi++] = v;
        if (qi == 4) {
            flush(4);
            qi = 0;
        }
    }
    if (qi > 0) flush(qi); 
    return out;
}

int main(int argc, char** argv) {
    // UPDATED: Now requires 3 arguments
    if (argc != 4) {
        std::cerr << "Usage:\n  verify_cli <payload_signed> <final_signature_b64> <public_key_b64>\n";
        return 2;
    }
    const std::string payload = argv[1];
    std::string sig_b64 = argv[2];
    std::string pub_b64 = argv[3]; // The public key from the JSON response

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