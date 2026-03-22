#include <algorithm>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

#include <openssl/sha.h>

#include "httplib.h"
#include "json.hpp"
#include "frost_ffi.h"

using json = nlohmann::json;

static inline int b64val(int c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static std::vector<uint8_t> b64dec(std::string s) {
    s.erase(std::remove_if(s.begin(), s.end(), [](unsigned char ch) {
        return ch == '\n' || ch == '\r' || ch == '\t' || ch == ' ';
    }), s.end());

    std::vector<uint8_t> out;
    out.reserve(s.size() * 3 / 4);

    int q[4];
    int qi = 0;
    int pad = 0;

    auto flush = [&](int valid) {
        if (valid < 2) return;
        int v0 = q[0], v1 = q[1], v2 = (valid > 2 ? q[2] : 0), v3 = (valid > 3 ? q[3] : 0);
        uint32_t triple = (uint32_t(v0) << 18) | (uint32_t(v1) << 12) |
                          (uint32_t(v2) << 6) | uint32_t(v3);
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


static void print_usage() {
    std::cout
        << "Usage:\n"
        << "  client_cli stamp <file> [server_url]\n"
        << "  client_cli verify <file> <receipt.json>\n";
}

static bool read_file_bytes(const std::string& path, std::vector<unsigned char>& out) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return false;
    }
    out.assign(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
    return true;
}

static bool read_text_file(const std::string& path, std::string& out) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return false;
    }
    out.assign(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
    return true;
}

static std::string sha256_hex(const std::vector<unsigned char>& data) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(data.data(), data.size(), digest);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char b : digest) {
        oss << std::setw(2) << static_cast<int>(b);
    }
    return oss.str();
}

static std::string default_receipt_path(const std::string& file_path) {
    return file_path + ".receipt.json";
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        print_usage();
        return 1;
    }

    const std::string command = argv[1];

    if (command == "stamp") {
        const std::string file = argv[2];
        const std::string server_url = (argc >= 4) ? argv[3] : "http://localhost:8081";

        std::vector<unsigned char> file_bytes;
        if (!read_file_bytes(file, file_bytes)) {
            std::cerr << "Error: cannot open file: " << file << "\n";
            return 1;
        }

        const std::string hash_hex = sha256_hex(file_bytes);

        httplib::Client cli(server_url);
        json request_body = {
            {"document_hash", hash_hex}
        };

        auto response = cli.Post("/timestamp", request_body.dump(), "application/json");
        if (!response) {
            std::cerr << "Error: request to " << server_url << "/timestamp failed\n";
            return 1;
        }

        if (response->status != 200) {
            std::cerr << "Error: server returned HTTP " << response->status << "\n";
            std::cerr << response->body << "\n";
            return 1;
        }

        const std::string receipt_path = default_receipt_path(file);
        std::ofstream receipt_out(receipt_path, std::ios::binary);
        if (!receipt_out) {
            std::cerr << "Error: cannot write receipt file: " << receipt_path << "\n";
            return 1;
        }

        receipt_out << response->body;
        receipt_out.close();

        std::cout << "Receipt saved to: " << receipt_path << "\n";
        return 0;
    }

    if (command == "verify") {
        if (argc < 4) {
            print_usage();
            return 1;
        }

        const std::string file = argv[2];
        const std::string receipt = argv[3];

        std::vector<unsigned char> file_bytes;
        if (!read_file_bytes(file, file_bytes)) {
            std::cerr << "Error: cannot open file: " << file << "\n";
            return 1;
        }

        std::string receipt_text;
        if (!read_text_file(receipt, receipt_text)) {
            std::cerr << "Error: cannot open receipt file: " << receipt << "\n";
            return 1;
        }

        const std::string hash_hex = sha256_hex(file_bytes);

        json receipt_json;
        try {
            receipt_json = json::parse(receipt_text);
        } catch (const std::exception& e) {
            std::cerr << "Error: invalid receipt JSON: " << e.what() << "\n";
            return 1;
        }

        if (!receipt_json.contains("status") ||
            !receipt_json.contains("timestamp") ||
            !receipt_json.contains("payload_signed") ||
            !receipt_json.contains("final_signature_b64") ||
            !receipt_json.contains("public_key_b64")) {
            std::cerr << "Error: receipt missing required fields\n";
            return 1;
        }

        const std::string status = receipt_json["status"].get<std::string>();
        const long long timestamp = receipt_json["timestamp"].get<long long>();
        const std::string payload_signed = receipt_json["payload_signed"].get<std::string>();
        const std::string final_signature_b64 = receipt_json["final_signature_b64"].get<std::string>();
        const std::string public_key_b64 = receipt_json["public_key_b64"].get<std::string>();

        if (status != "success") {
            std::cerr << "Error: receipt status is not success\n";
            return 1;
        }

        const std::string expected_payload = hash_hex + "_TIME_" + std::to_string(timestamp);

        if (payload_signed != expected_payload) {
            std::cerr << "INVALID: payload mismatch\n";
            std::cerr << "expected=" << expected_payload << "\n";
            std::cerr << "actual=" << payload_signed << "\n";
            return 1;
        }

        auto sig = b64dec(final_signature_b64);
        if (sig.size() != 64) {
            std::cerr << "Error: invalid signature length: " << sig.size() << "\n";
            return 1;
        }

        auto pub_pkg = b64dec(public_key_b64);
        if (pub_pkg.empty()) {
            std::cerr << "Error: invalid public key encoding\n";
            return 1;
        }

        int rc = frost_verify(
            reinterpret_cast<const uint8_t*>(payload_signed.data()),
            payload_signed.size(),
            sig.data(),
            sig.size(),
            pub_pkg.data(),
            pub_pkg.size()
        );

        if (rc != 0) {
            std::cerr << "INVALID: signature verification failed\n";
            return 1;
        }

        std::cout << "VALID\n";
        return 0;
    }

    print_usage();
    return 1;
}
