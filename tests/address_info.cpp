//
// Created by sigma on 1/14/2021.
//

#include <gtest/gtest.h>
#include <network.h>

TEST(address_info, resolve) {
    network::init();

    auto a = network::address_info();

    if(auto e = a.resolve("www.google.com")) {
        network::shutdown();
        FAIL() << e->message();
    }

    if(auto e = a.resolve("www.google.com", "80")) {
        network::shutdown();
        FAIL() << e->message();
    }

    network::shutdown();
}