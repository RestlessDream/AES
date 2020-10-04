#include "unity.h"
#include "../src/aes.h"
#include "../src/util.h"
#include "stdio.h"

extern standart_config AES_192;
extern standart_config * AES;
extern size_t state_rows;

void setUp(void) {
    setup(&AES_192);
}

void tearDown(void) {
}

void test_key_expansion() {
    byte key[24] = { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b };

    word * w = malloc(AES->key_length * (AES->rounds + 1) * sizeof(word));

    key_expansion(key, w);
    word expected[52] = { 0x8e73b0f7, 0xda0e6452, 0xc810f32b, 0x809079e5, 0x62f8ead2, 0x522c6b7b, 0xfe0c91f7, 0x2402f5a5, 0xec12068e,  0x6c827f6b, 0x0e7a95b9, 0x5c56fec2, 0x4db7b4bd, 0x69b54118, 0x85a74796, 0xe92538fd, 0xe75fad44, 0xbb095386, 0x485af057, 0x21efb14f, 0xa448f6d9, 0x4d6dce24, 0xaa326360, 0x113b30e6, 0xa25e7ed5, 0x83b1cf9a, 0x27f93943, 0x6a94f767, 0xc0a69407, 0xd19da4e1, 0xec1786eb, 0x6fa64971, 0x485f7032, 0x22cb8755, 0xe26d1352, 0x33f0b7b3, 0x40beeb28, 0x2f18a259, 0x6747d26b, 0x458c553e, 0xa7e1466c, 0x9411f1df, 0x821f750a, 0xad07d753, 0xca400538, 0x8fcc5006, 0x282d166a, 0xbc3ce7b5, 0xe98ba06f, 0x448c773c, 0x8ecc7204, 0x01002202 };

    TEST_ASSERT_EQUAL_UINT32_ARRAY(expected, w, 52);
}

void test_cipher() {
    byte key[24] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
    byte block[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    byte expected[16] = { 0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91 };
    byte out[16];
    word * w = malloc(AES->block_wsize * (AES->rounds + 1) * sizeof(word));

    key_expansion(key, w);

    cipher(block, out, w);

    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, out, 16);
}

void test_inv_cipher() {
    byte key[24] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
    byte block[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    byte out[16];
    byte res[16];
    word * w = malloc(AES->block_wsize * (AES->rounds + 1) * sizeof(word));

    key_expansion(key, w);

    cipher(block, out, w);
    inv_cipher(out, res, w);

    TEST_ASSERT_EQUAL_UINT8_ARRAY(block, res, 16);
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_key_expansion);
    RUN_TEST(test_cipher);
    RUN_TEST(test_inv_cipher);

    return UNITY_END();
}