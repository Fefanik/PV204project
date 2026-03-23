#include "client_cli.h"

#include <algorithm>
#include <iostream>
#include <iomanip>
#include <sstream>

#include <openssl/sha.h>

#include "httplib.h"
#include "frost_ffi.h"
#include "base64.h"

using json = nlohmann::json;

void print_usage() {
    std::cout
        << "Usage:\n"
        << "  client_cli stamp <file> [server_url]\n"
        << "  client_cli verify <file> <receipt.json>\n";
}

std::string sha256_hex(const std::vector<unsigned char>& data) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(data.data(), data.size(), digest);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char b : digest) {
        oss << std::setw(2) << static_cast<int>(b);
    }
    return oss.str();
}

std::optional<std::string> calculate_file_hash(const std::string& filepath) {
    std::vector<unsigned char> file_bytes;
    if (!read_file(filepath, file_bytes)) {
        std::cerr << "Error: cannot open file: " << filepath << "\n";
        return std::nullopt;
    }
    return sha256_hex(file_bytes);
}

std::string default_receipt_path(const std::string& file_path) {
    return file_path + ".receipt.json";
}

bool validate_receipt_fields(const json& receipt_json) {
    if (!receipt_json.contains("status") ||
        !receipt_json.contains("timestamp") ||
        !receipt_json.contains("payload_signed") ||
        !receipt_json.contains("final_signature_b64") ||
        !receipt_json.contains("public_key_b64")) {
        std::cerr << "Error: receipt missing required fields\n";
        return false;
    }
    return true;
}

int handle_stamp(const std::string& file, const std::string& server_url) {
    auto hash_hex_opt = calculate_file_hash(file);
    if (!hash_hex_opt) return 1;

    httplib::Client cli(server_url);
    json request_body = {
        {"document_hash", *hash_hex_opt}
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

    json receipt_json;
    try {
        receipt_json = json::parse(response->body);
    } catch (const std::exception& e) {
        std::cerr << "Error: invalid JSON response from server: " << e.what() << "\n";
        return 1;
    }

    if (!validate_receipt_fields(receipt_json)) {
        return 1;
    }

    const std::string receipt_path = default_receipt_path(file);
    std::ofstream receipt_out(receipt_path, std::ios::binary);
    if (!receipt_out) {
        std::cerr << "Error: cannot write receipt file: " << receipt_path << "\n";
        return 1;
    }

    receipt_out << receipt_json.dump(4);
    receipt_out.close();

    std::cout << "Receipt saved to: " << receipt_path << "\n";
    return 0;
}

int handle_verify(const std::string& file, const std::string& receipt_path) {
    auto hash_hex_opt = calculate_file_hash(file);
    if (!hash_hex_opt) return 1;

    std::string receipt_text;
    if (!read_file(receipt_path, receipt_text)) {
        std::cerr << "Error: cannot open receipt file: " << receipt_path << "\n";
        return 1;
    }

    json receipt_json;
    try {
        receipt_json = json::parse(receipt_text);
    } catch (const std::exception& e) {
        std::cerr << "Error: invalid receipt JSON: " << e.what() << "\n";
        return 1;
    }

    if (!validate_receipt_fields(receipt_json)) {
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

    const std::string expected_payload = *hash_hex_opt + "_TIME_" + std::to_string(timestamp);

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

int main(int argc, char* argv[]) {
    if (argc < 3) {
        print_usage();
        return 1;
    }

    const std::string command = argv[1];

    if (command == "stamp") {
        const std::string file = argv[2];
        const std::string server_url = (argc >= 4) ? argv[3] : "http://localhost:8081";
        return handle_stamp(file, server_url);
    }

    if (command == "verify") {
        if (argc < 4) {
            print_usage();
            return 1;
        }
        const std::string file = argv[2];
        const std::string receipt = argv[3];
        return handle_verify(file, receipt);
    }

    print_usage();
    return 1;
}
