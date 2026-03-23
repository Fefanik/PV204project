#pragma once

#include <vector>
#include <string>
#include <cstdint>

/**
 * @brief Converts a base64 character to its integer value.
 * 
 * @param c The character to convert.
 * @return int The 6-bit integer value (0-63) of the base64 character. 
 *         Returns -1 if the character is not a valid base64 character.
 */
int b64val(int c);

/**
 * @brief Decodes a Base64-encoded string into raw binary data.
 * 
 * @param s The Base64-encoded input string. Passed by value as it is mutated internally.
 * @return std::vector<uint8_t> A vector containing the decoded bytes.
 */
std::vector<uint8_t> b64dec(std::string s);