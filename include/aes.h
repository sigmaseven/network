//
// Created by sigma on 1/18/2021.
//

#ifndef NETWORK_AES_H
#define NETWORK_AES_H

#include <iostream>

#include <emmintrin.h>
#include <wmmintrin.h>

#define expand_key_128(key, round) \
    aes_128_key_expansion(key, _mm_aeskeygenassist_si128(key, round));

namespace aes {

    enum cipher {
        AES128 = 10,
        AES192 = 12,
        AES256 = 14
    };

    typedef enum cipher cipher_t;
    typedef std::vector<std::uint8_t> bytes_t;

    bytes_t to_bytes(const std::string &input) {
        auto result = bytes_t();

        for (const auto &c : input) {
            result.push_back(c);
        }

        return result;
    }

    bool is_on_chip() {
#ifdef LINUX
        return __builtin_cpu_supports("aes");
#endif //LINUX

#ifdef WINDOWS
#ifdef MSVC
        std::vector<int> registers(4);

        __cpuid(registers.data(), 0x01);
        return ((registers[2] & 0x2000000);
#else
        return __builtin_cpu_supports("aes");
#endif
#endif //WINDOWS
    }

    static __m128i aes_128_key_expansion(__m128i key, __m128i keygened){
        keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3,3,3,3));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
        return _mm_xor_si128(key, keygened);
    }

    static std::vector<__m128i> generate_keys_128(bytes_t& key) {
        auto schedule = std::vector<__m128i>(21);

        schedule[0]  = _mm_loadu_si128((__m128i*)key.data());
        schedule[1]  = expand_key_128(schedule[0], 0x01);
        schedule[2]  = expand_key_128(schedule[1], 0x02);
        schedule[3]  = expand_key_128(schedule[2], 0x04);
        schedule[4]  = expand_key_128(schedule[3], 0x08);
        schedule[5]  = expand_key_128(schedule[4], 0x10);
        schedule[6]  = expand_key_128(schedule[5], 0x20);
        schedule[7]  = expand_key_128(schedule[6], 0x40);
        schedule[8]  = expand_key_128(schedule[7], 0x80);
        schedule[9]  = expand_key_128(schedule[8], 0x1B);
        schedule[10] = expand_key_128(schedule[9], 0x36);

    }
}
#endif //NETWORK_AES_H
