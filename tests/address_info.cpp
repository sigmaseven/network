//
// Created by sigma on 1/14/2021.
//

#include <gtest/gtest.h>
#include <network.h>
#include <aes.h>

TEST(address_info, resolve) {
    auto a = network::address_info();

    if(auto e = a.resolve("www.google.com")) {
        FAIL() << e->message();
    }

    if(auto e = a.resolve("www.google.com", "80")) {
        FAIL() << e->message();
    }
}

TEST(aes, detect) {
    bool test = aes::is_on_chip();
    ASSERT_EQ(test, true);
}

TEST(aes, encrypt) {
    auto plaintext = aes::to_bytes("0123456789012345");

    __m128i key;

    key[0] = 0xDEADBEEF;
    key[1] = 0xBADCFFEE;

    auto c = aes::context(aes::AES128, key);

    auto encrypted = c.encrypt_block(plaintext, 10);
    auto decrypted = c.decrypt_block(encrypted, 10);
    ASSERT_EQ(plaintext,decrypted);
}