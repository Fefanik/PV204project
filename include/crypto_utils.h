#pragma once

#include <string>

/**
 * @brief Computes the SHA-256 hash of the input string.
 * 
 * @param input The raw input data.
 * @return std::string The hexadecimal representation of the SHA-256 hash.
 */
std::string sha256(const std::string &input);