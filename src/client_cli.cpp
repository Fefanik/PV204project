#include "client_cli.h"

#include <algorithm>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <filesystem>

#include <openssl/sha.h>

#include "httplib.h"
#include "frost_ffi.h"
#include "base64.h"

using json = nlohmann::json;


std::string sha256_string(const std::string &input) {
    std::vector<unsigned char> vec(input.begin(), input.end());
    return sha256_hex(vec);
}

std::string cert_dir() {
    const char* home = getenv("HOME");
    std::string base_dir = home ? std::string(home) : ".";
    return base_dir + "/.frost_certs";
}

std::string cert_path_for_node(const std::string &node_id) {
    return cert_dir() + "/server_" + node_id + ".cert.json";
}
void ensure_cert_dir() {
    std::filesystem::create_directories(cert_dir());
}

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

    // -----------------------------------------------
    // Extract certificate from server response (new)
    // -----------------------------------------------
    if (!receipt_json.contains("certificate")) {
        std::cerr << "Error: server did not send a certificate\n";
        return 1;
    }

    json cert_json = receipt_json["certificate"];
    int node_int = cert_json["node_id"].get<int>();
    std::string node_id = std::to_string(node_int);

    // Ensure certificate directory exists
    ensure_cert_dir();

    // Build certificate path
    std::string cert_path = cert_path_for_node(node_id);

    // Save certificate
    std::ofstream cert_out(cert_path);
    if (!cert_out) {
        std::cerr << "Error: cannot write certificate file: " << cert_path << "\n";
        return 1;
    }
    cert_out << cert_json.dump(4);
    cert_out.close();

    std::cout << "Certificate saved to: " << cert_path << "\n";

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

    if (!receipt_json.contains("certificate")) {
        std::cerr << "Error: receipt missing certificate\n";
        return 1;
    }

    json received_cert = receipt_json["certificate"];
    int node_int = received_cert["node_id"].get<int>();
    std::string node_id = std::to_string(node_int);

    std::string stored_cert_path = cert_path_for_node(node_id);
    std::string stored_cert_text;

    if (!read_file(stored_cert_path, stored_cert_text)) {
        std::cerr << "Error: cannot open stored certificate: " << stored_cert_path << "\n";
        std::cerr << "You must stamp at least once first.\n";
        return 1;
    }

    json stored_cert;
    try {
        stored_cert = json::parse(stored_cert_text);
    } catch (...) {
        std::cerr << "Error: stored certificate is invalid JSON\n";
        return 1;
    }

    int stored_id_int = stored_cert["node_id"].get<int>();
    std::string stored_id = std::to_string(stored_id_int);
    std::string stored_pub = stored_cert["pub_key_b64"].get<std::string>();
    std::string stored_fp  = stored_cert["fingerprint"].get<std::string>();

    std::string recomputed_fp = sha256_string(stored_id + stored_pub);

    if (recomputed_fp != stored_fp) {
        std::cerr << "INVALID: stored certificate fingerprint mismatch (tampering)\n";
        return 1;
    }

    int recv_id_int = received_cert["node_id"].get<int>();
    std::string recv_id = std::to_string(recv_id_int);
    std::string recv_pub = received_cert["pub_key_b64"].get<std::string>();
    std::string recv_fp  = received_cert["fingerprint"].get<std::string>();

    if (recv_id != stored_id || recv_pub != stored_pub || recv_fp != stored_fp) {
        std::cerr << "INVALID: certificate mismatch (server key changed!)\n";
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
