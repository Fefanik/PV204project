#include <gtest/gtest.h>
#include "crypto_utils.h"

TEST(CryptoTest, Sha256EmptyString) {
    std::string expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    EXPECT_EQ(sha256(""), expected);
}

TEST(CryptoTest, Sha256KnownText) {
    std::string expected = "25b01d074c96537518941dda461b5d9058d0e1177a076c13561a98cbe8703cfe";
    EXPECT_EQ(sha256("PV204"), expected);
}