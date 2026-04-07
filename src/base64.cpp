#include "base64.h"
#include <algorithm>

// ---- tiny Base64 (KISS, for JSON wire) ----
static const char* B64 =
 "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string b64enc(const uint8_t* data, size_t len){
    std::string out; out.reserve(((len+2)/3)*4);
    for(size_t i=0;i<len;i+=3){
        uint32_t v=(data[i]<<16);
        if(i+1<len) v|=(data[i+1]<<8);
        if(i+2<len) v|=(data[i+2]);
        out.push_back(B64[(v>>18)&63]);
        out.push_back(B64[(v>>12)&63]);
        out.push_back((i+1<len)?B64[(v>>6)&63]:'=');
        out.push_back((i+2<len)?B64[v&63]:'=');
    }
    return out;
}

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