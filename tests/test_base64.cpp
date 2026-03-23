#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "base64.h"

// Helper to convert vector<uint8_t> back to string for easy comparison
std::string vec_to_str(const std::vector<uint8_t>& vec) {
    return std::string(vec.begin(), vec.end());
}

TEST(Base64Test, ValidInput) {
    auto out = b64dec("SGVsbG8=");
    EXPECT_EQ(vec_to_str(out), "Hello");
}

TEST(Base64Test, WithSpacesAndNewlines) {
    auto out = b64dec("VG Vzd\nGlu\tZw==");
    EXPECT_EQ(vec_to_str(out), "Testing");
}

TEST(Base64Test, MissingPadding) {
    auto out = b64dec("VGVzdA");
    EXPECT_EQ(vec_to_str(out), "Test");
}

TEST(Base64Test, InvalidCharactersIgnored) {
    auto out = b64dec("S?Gk=!");
    EXPECT_EQ(vec_to_str(out), "Hi");
}