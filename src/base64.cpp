#include "base64.h"
#include <algorithm>

int b64val(int c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1; 
}

std::vector<uint8_t> b64dec(std::string s) {
    // Remove whitespace characters
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