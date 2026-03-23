#pragma once

#include <string>
#include <vector>
#include <optional>
#include <fstream>
#include "json.hpp"

/**
 * @brief Prints the usage instructions for the client CLI.
 */
void print_usage();

/**
 * @brief Reads the entire contents of a file into a container (e.g., std::string or std::vector).
 * 
 * @tparam Container The type of the container to read into.
 * @param path The filesystem path to the file.
 * @param out The container where the file contents will be stored.
 * @return true If the file was successfully opened and read.
 * @return false If the file could not be opened.
 */
template <typename Container>
bool read_file(const std::string& path, Container& out) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return false;
    }
    out.assign(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
    return true;
}

/**
 * @brief Calculates the SHA-256 hash of raw byte data.
 * 
 * @param data A vector containing the raw bytes to hash.
 * @return std::string The resulting SHA-256 hash as a lowercase hex string.
 */
std::string sha256_hex(const std::vector<unsigned char>& data);

/**
 * @brief Reads a file from disk and returns its SHA-256 hash in hex format.
 * 
 * @param filepath The path to the file to hash.
 * @return std::optional<std::string> The hex string of the hash if successful, or std::nullopt if the file could not be read.
 */
std::optional<std::string> calculate_file_hash(const std::string& filepath);

/**
 * @brief Generates the default file path for the receipt based on the target file.
 * 
 * @param file_path The path to the original file.
 * @return std::string The default receipt path (e.g., "document.pdf.receipt.json").
 */
std::string default_receipt_path(const std::string& file_path);

/**
 * @brief Checks if the JSON object contains all required fields for a valid receipt.
 * 
 * @param receipt_json The parsed JSON object to validate.
 * @return true If all required fields ("status", "timestamp", "payload_signed", etc.) are present.
 * @return false If any required field is missing.
 */
bool validate_receipt_fields(const nlohmann::json& receipt_json);

/**
 * @brief Handles the 'stamp' command: hashes a file and requests a timestamp signature from the server.
 * 
 * @param file The path to the file to stamp.
 * @param server_url The URL of the timestamping server.
 * @return int 0 on success, 1 on failure.
 */
int handle_stamp(const std::string& file, const std::string& server_url);

/**
 * @brief Handles the 'verify' command: checks a file against its signed JSON receipt.
 * 
 * @param file The path to the file to verify.
 * @param receipt_path The path to the corresponding receipt JSON file.
 * @return int 0 on success (VALID), 1 on failure (INVALID or error).
 */
int handle_verify(const std::string& file, const std::string& receipt_path);