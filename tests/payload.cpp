//
// Created by sigma on 1/14/2021.
//

#include <gtest/gtest.h>
#include <network.h>
#include <utility>
#include <string>

class mock_serializable : public network::serializable {
public:
    std::uint32_t a;
    std::string b;

    mock_serializable() : a(0x04), b(std::string("test")) {}
    std::optional<network::error> serialize(network::payload& p) override {
        p.write(a, network::endian::LITTLE);
        p.write(b);

        return std::nullopt;
    }

    std::optional<network::error> deserialize(network::payload& p) override {
        p.read(a, network::endian::LITTLE);
        p.read(b, a);
        return std::nullopt;
    }

    std::size_t size() override {
        return sizeof(a) + b.size();
    }
};

TEST(payload, write_uint8_t) {
    network::init();

    auto p = network::payload();
    std::uint8_t value;

    value = 0x11;

    if(auto e = p.write(value)) {
        network::shutdown();
        FAIL() << e->message();
    }


    ASSERT_EQ(p.contents()[0], 0x11);
    network::shutdown();
}

TEST(payload, write_int8_t) {
    network::init();

    auto p = network::payload();
    std::int8_t value;

    value = 0xEE;

    if(auto e = p.write(value)) {
        network::shutdown();
        FAIL() << e->message();
    }


    ASSERT_EQ(p.contents()[0], 0xEE);
    network::shutdown();
}

TEST(payload, write_uint16_t) {
    network::init();

    auto p1 = network::payload();
    std::uint16_t value = 0x1122;

    if(auto e = p1.write(value, network::LITTLE)) {
        FAIL() << e->message();
    }

    ASSERT_EQ(p1.contents()[0], 0x22);
    ASSERT_EQ(p1.contents()[1], 0x11);

    p1.reset();

    if(auto e = p1.write(value, network::BIG)) {
        network::shutdown();
        FAIL() << e->message();
    }

    ASSERT_EQ(p1.contents()[0], 0x11);
    ASSERT_EQ(p1.contents()[1], 0x22);
    network::shutdown();
}

TEST(payload, write_int16_t) {
    network::init();

    auto p1 = network::payload();
    std::int16_t value = 0xDEAD;

    if(auto e = p1.write(value, network::LITTLE)) {
        network::shutdown();
        FAIL() << e->message();
    }

    ASSERT_EQ(p1.contents()[0], 0xAD);
    ASSERT_EQ(p1.contents()[1], 0xDE);

    p1.reset();

    if(auto e = p1.write(value, network::BIG)) {
        network::shutdown();
        FAIL() << e->message();
    }

    ASSERT_EQ(p1.contents()[0], 0xDE);
    ASSERT_EQ(p1.contents()[1], 0xAD);
    network::shutdown();
}

TEST(payload, write_uint32_t) {
    network::init();

    auto p1 = network::payload();
    std::uint32_t value = 0x11223344;

    if(auto e = p1.write(value, network::LITTLE)) {
        network::shutdown();
        FAIL() << e->message();
    }

    ASSERT_EQ(p1.contents()[0], 0x44);
    ASSERT_EQ(p1.contents()[1], 0x33);
    ASSERT_EQ(p1.contents()[2], 0x22);
    ASSERT_EQ(p1.contents()[3], 0x11);

    p1.reset();

    if(auto e = p1.write(value, network::BIG)) {
        network::shutdown();
        FAIL() << e->message();
    }

    ASSERT_EQ(p1.contents()[0], 0x11);
    ASSERT_EQ(p1.contents()[1], 0x22);
    ASSERT_EQ(p1.contents()[2], 0x33);
    ASSERT_EQ(p1.contents()[3], 0x44);
}

TEST(payload, write_int32_t) {
    network::init();

    auto p1 = network::payload();
    std::int32_t value = 0xDEADBEEF;

    if(auto e = p1.write(value, network::BIG)) {
        network::shutdown();
        FAIL() << e->message();
    }

    ASSERT_EQ(p1.contents()[0], 0xDE);
    ASSERT_EQ(p1.contents()[1], 0xAD);
    ASSERT_EQ(p1.contents()[2], 0xBE);
    ASSERT_EQ(p1.contents()[3], 0xEF);

    p1.reset();

    if(auto e = p1.write(value, network::LITTLE)) {
        network::shutdown();
        FAIL() << e->message();
    }

    ASSERT_EQ(p1.contents()[0], 0xEF);
    ASSERT_EQ(p1.contents()[1], 0xBE);
    ASSERT_EQ(p1.contents()[2], 0xAD);
    ASSERT_EQ(p1.contents()[3], 0xDE);
}

TEST(payload, write_uint64_t) {
    network::init();

    auto p1 = network::payload();
    std::uint64_t value = 0x1122334455667788;

    if(auto e = p1.write(value, network::LITTLE)) {
        network::shutdown();
        FAIL() << e->message();
    }

    if(network::platform_endianness() == network::LITTLE) {
        ASSERT_EQ(p1.contents()[0], 0x88);
        ASSERT_EQ(p1.contents()[1], 0x77);
        ASSERT_EQ(p1.contents()[2], 0x66);
        ASSERT_EQ(p1.contents()[3], 0x55);
        ASSERT_EQ(p1.contents()[4], 0x44);
        ASSERT_EQ(p1.contents()[5], 0x33);
        ASSERT_EQ(p1.contents()[6], 0x22);
        ASSERT_EQ(p1.contents()[7], 0x11);
    } else {
        ASSERT_EQ(p1.contents()[0], 0x11);
        ASSERT_EQ(p1.contents()[1], 0x22);
        ASSERT_EQ(p1.contents()[2], 0x33);
        ASSERT_EQ(p1.contents()[3], 0x44);
        ASSERT_EQ(p1.contents()[4], 0x55);
        ASSERT_EQ(p1.contents()[5], 0x66);
        ASSERT_EQ(p1.contents()[6], 0x77);
        ASSERT_EQ(p1.contents()[7], 0x88);
    }
}

TEST(payload, write_int64_t) {
    network::init();

    auto p1 = network::payload();

    std::uint64_t value = 0xDEADBEEF11223344;

    if(auto e = p1.write(value, network::BIG)) {
        network::shutdown();
        FAIL() << e->message();
    }

    ASSERT_EQ(p1.contents()[0], 0xDE);
    ASSERT_EQ(p1.contents()[1], 0xAD);
    ASSERT_EQ(p1.contents()[2], 0xBE);
    ASSERT_EQ(p1.contents()[3], 0xEF);
    ASSERT_EQ(p1.contents()[4], 0x11);
    ASSERT_EQ(p1.contents()[5], 0x22);
    ASSERT_EQ(p1.contents()[6], 0x33);
    ASSERT_EQ(p1.contents()[7], 0x44);

    p1.reset();

    if(auto e = p1.write(value, network::LITTLE)) {
        network::shutdown();
        FAIL() << e->message();
    }

    ASSERT_EQ(p1.contents()[0], 0x44);
    ASSERT_EQ(p1.contents()[1], 0x33);
    ASSERT_EQ(p1.contents()[2], 0x22);
    ASSERT_EQ(p1.contents()[3], 0x11);
    ASSERT_EQ(p1.contents()[4], 0xEF);
    ASSERT_EQ(p1.contents()[5], 0xBE);
    ASSERT_EQ(p1.contents()[6], 0xAD);
    ASSERT_EQ(p1.contents()[7], 0xDE);
    network::shutdown();
}

TEST(payload, write_string) {
    network::init();

    auto p = network::payload();
    auto s = std::string("boop");

    if(auto e = p.write(s)) {
        network::shutdown();
        FAIL() << e->message();
    }

    ASSERT_EQ(p.contents()[0], (unsigned char)'b');
    ASSERT_EQ(p.contents()[1], (unsigned char)'o');
    ASSERT_EQ(p.contents()[2], (unsigned char)'o');
    ASSERT_EQ(p.contents()[3], (unsigned char)'p');
}

TEST(payload, write_vector) {
    network::init();

    auto p = network::payload();
    auto v = std::vector<std::uint8_t>({'b', 'o', 'o', 'p'});

    if(auto e = p.write(v)) {
        network::shutdown();
        FAIL() << e->message();
    }

    ASSERT_EQ(p.contents()[0], (unsigned char)'b');
    ASSERT_EQ(p.contents()[1], (unsigned char)'o');
    ASSERT_EQ(p.contents()[2], (unsigned char)'o');
    ASSERT_EQ(p.contents()[3], (unsigned char)'p');
}

TEST(payload, write_serializable) {
    network::init();

    auto p = network::payload();
    auto m = mock_serializable();

    if(auto e = p.write(m)) {
        network::shutdown();
        FAIL() << e->message();
    }

    ASSERT_EQ(p.contents()[0], 0x04);
    ASSERT_EQ(p.contents()[1], 0x00);
    ASSERT_EQ(p.contents()[2], 0x00);
    ASSERT_EQ(p.contents()[3], 0x00);
    ASSERT_EQ(p.contents()[4], (unsigned char)'t');
    ASSERT_EQ(p.contents()[5], (unsigned char)'e');
    ASSERT_EQ(p.contents()[6], (unsigned char)'s');
    ASSERT_EQ(p.contents()[7], (unsigned char)'t');
    network::shutdown();
}

TEST(payload, read_uint8_t) {
    network::init();

    auto p = network::payload();

    std::uint8_t value = 0x11;
    std::uint8_t result;

    if(auto e = p.write(value)) {
        network::shutdown();
        FAIL() << e->message();
    }

    if(auto e = p.read(result)) {
        network::shutdown();
        FAIL() << e->message();
    }

    ASSERT_EQ(result, 0x11);
    network::shutdown();
}

TEST(payload, read_uint16_t) {
    network::init();

    auto p1 = network::payload();
    std::uint16_t v1 = 0x1122;
    std::uint16_t v2 = 0;

    if(auto e = p1.write(v1, network::LITTLE)) {
        network::shutdown();
        FAIL() << e->message();
    }

    if(auto e = p1.read(v2, network::LITTLE)) {
        network::shutdown();
        FAIL() << e->message();
    }

    ASSERT_EQ(v2, 0x1122);

    p1.reset();

    if(auto e = p1.write(v1, network::BIG)) {
        network::shutdown();
        FAIL() << e->message();
    }

    if(auto e = p1.read(v2, network::BIG)) {
        network::shutdown();
        FAIL() << e->message();
    }

    ASSERT_EQ(v2, 0x1122);
    network::shutdown();
}

TEST(payload, read_uint32_t) {
    network::init();

    auto p1 = network::payload();
    std::uint32_t v1 = 0x11223344;
    std::uint32_t v2 = 0;

    if(auto e = p1.write(v1, network::LITTLE)) {
        network::shutdown();
        FAIL() << e->message();
    }

    if(auto e = p1.read(v2, network::LITTLE)) {
        network::shutdown();
        FAIL() << e->message();
    }

    ASSERT_EQ(v2, 0x11223344);

    p1.reset();

    if(auto e = p1.write(v1, network::BIG)) {
        network::shutdown();
        FAIL() << e->message();
    }

    if(auto e = p1.read(v2, network::BIG)) {
        network::shutdown();
        FAIL() << e->message();
    }

    ASSERT_EQ(v2, 0x11223344);
    network::shutdown();
}

TEST(payload, read_uint64_t) {
    network::init();

    auto p1 = network::payload();
    std::uint64_t v1 = 0x11223344556677;
    std::uint64_t v2 = 0;

    if(auto e = p1.write(v1, network::LITTLE)) {
        network::shutdown();
        FAIL() << e->message();
    }

    if(auto e = p1.read(v2, network::LITTLE)) {
        network::shutdown();
        FAIL() << e->message();
    }

    ASSERT_EQ(v2, 0x11223344556677);

    p1.reset();

    if(auto e = p1.write(v1, network::BIG)) {
        network::shutdown();
        FAIL() << e->message();
    }

    if(auto e = p1.read(v2, network::BIG)) {
        network::shutdown();
        FAIL() << e->message();
    }

    ASSERT_EQ(v2, 0x11223344556677);
    network::shutdown();
}

TEST(payload, read_serializable) {
    network::init();

    auto p = network::payload();
    auto m1 = mock_serializable();
    auto m2 = mock_serializable();

    if(auto e = p.write(m1)) {
        network::shutdown();
        FAIL() << e->message();
    }

    m2.a = 0;
    m2.b = "";

    if(auto e = p.read(m2)) {
        network::shutdown();
        FAIL() << e->message();
    }

    ASSERT_EQ(m2.a, 4);
    ASSERT_EQ(m2.b, "test");
    network::shutdown();
}

TEST(payload, concatenate) {
    network::init();

    auto p1 = network::payload(network::endian::BIG);
    auto p2 = network::payload(network::endian::BIG);
    auto s1 = std::string("beep");
    auto s2 = std::string("boop");

    if(auto e = p1.write(s1)) {
        network::shutdown();
        FAIL() << e->message();
    }

    if(auto e = p2.write(s2)) {
        network::shutdown();
        FAIL() << e->message();
    }

    auto p3 = p1 + p2;

    ASSERT_EQ(p3.contents().size(), 8);
    ASSERT_EQ(p3.contents()[0], (unsigned char)'b');
    ASSERT_EQ(p3.contents()[1], (unsigned char)'e');
    ASSERT_EQ(p3.contents()[2], (unsigned char)'e');
    ASSERT_EQ(p3.contents()[3], (unsigned char)'p');
    ASSERT_EQ(p3.contents()[4], (unsigned char)'b');
    ASSERT_EQ(p3.contents()[5], (unsigned char)'o');
    ASSERT_EQ(p3.contents()[6], (unsigned char)'o');
    ASSERT_EQ(p3.contents()[7], (unsigned char)'p');
    network::shutdown();
}