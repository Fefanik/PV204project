#include <gtest/gtest.h>
#include <string>
#include <vector>
#include <cstring>

#include "base64.h"

// Helper to convert vector<uint8_t> back to string for easy comparison
std::string vec_to_str(const std::vector<uint8_t>& vec) {
    return std::string(vec.begin(), vec.end());
}

// Helper to convert string to uint8_t pointer for encoding
const uint8_t* str_to_u8(const char* str) {
    return reinterpret_cast<const uint8_t*>(str);
}

// Decoding tests
TEST(Base64DecodeTest, ValidInput) {
    auto out = b64dec("SGVsbG8=");
    EXPECT_EQ(vec_to_str(out), "Hello");
}

TEST(Base64DecodeTest, WithSpacesAndNewlines) {
    auto out = b64dec("VG Vzd\nGlu\tZw==");
    EXPECT_EQ(vec_to_str(out), "Testing");
}

TEST(Base64DecodeTest, MissingPadding) {
    auto out = b64dec("VGVzdA");
    EXPECT_EQ(vec_to_str(out), "Test");
}

TEST(Base64DecodeTest, InvalidCharactersIgnored) {
    auto out = b64dec("S?Gk=!");
    EXPECT_EQ(vec_to_str(out), "Hi");
}

TEST(Base64DecodeTest, EmptyString) {
    auto out = b64dec("");
    EXPECT_TRUE(out.empty());
}

// Encoding tests
TEST(Base64EncodeTest, NoPaddingNeeded) {
    const char* input = "abc";
    std::string out = b64enc(str_to_u8(input), std::strlen(input));
    EXPECT_EQ(out, "YWJj");
}

TEST(Base64EncodeTest, OnePaddingCharNeeded) {
    const char* input = "ab";
    std::string out = b64enc(str_to_u8(input), std::strlen(input));
    EXPECT_EQ(out, "YWI=");
}

TEST(Base64EncodeTest, TwoPaddingCharsNeeded) {
    const char* input = "a";
    std::string out = b64enc(str_to_u8(input), std::strlen(input));
    EXPECT_EQ(out, "YQ==");
}

TEST(Base64EncodeTest, EmptyInput) {
    std::string out = b64enc(nullptr, 0);
    EXPECT_EQ(out, "");
}
