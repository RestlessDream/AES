#include "unity.h"
#include "../src/aes.h"
#include "../src/util.h"
#include "stdio.h"

extern standart_config AES_128;
extern standart_config * AES;
extern size_t state_rows;

void setUp(void) {
    setup(&AES_128);
}

void tearDown(void) {
}

void test_sub_bytes() {
    byte ** state = (byte **)malloc_2d(state_rows, (size_t)(sizeof(byte)*AES->block_wsize));

    byte el = 0xFF;
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] = el;
            el = el << 1;
        }
    }

    sub_bytes(state);
    TEST_ASSERT_EQUAL_UINT8(0x16, state[0][0]);
    TEST_ASSERT_EQUAL_UINT8(0xbb, state[0][1]);
    TEST_ASSERT_EQUAL_UINT8(0x63, state[3][3]);
    TEST_ASSERT_EQUAL_UINT8(0x8c, state[1][0]);

    free_2d((void **) state, state_rows);
}

void test_sub_word() {
    word test[10] = { 0xcf4f3c09, 0x6c76052a, 0x59f67f73, 0x7a883b6d, 0x0bad00db, 0xf915bc11, 0x0093fdca, 0xa6dc4f4e, 0x8d292f7f, 0x5c006e57 };
    word expected[10] = {0x8a84eb01, 0x50386be5, 0xcb42d28f, 0xdac4e23c, 0x2b9563b9, 0x99596582, 0x63dc5474, 0x2486842f, 0x5da515d2, 0x4a639f5b};

    for (int i = 0; i < 10; i++) {
        TEST_ASSERT_EQUAL_UINT32(expected[i], sub_word(test[i]));
    }
}

void test_shift_rows() {
    byte ** state = (byte **)malloc_2d(state_rows, (size_t)(sizeof(byte)*AES->block_wsize));

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] = j + i*4;
        }
    }

    shift_rows(state);

    byte expected1[4] = { 0, 1, 2, 3 };
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected1, state[0], 4);
    byte expected2[4] = { 5, 6, 7, 4 };
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected2, state[1], 4);
    byte expected3[4] = { 10, 11, 8, 9 };
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected3, state[2], 4);
    byte expected4[4] = { 15, 12, 13, 14 };
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected4, state[3], 4);

    free_2d((void **) state, state_rows);
}

void test_mix_columns() {
    byte ** state = (byte **)malloc_2d(state_rows, (size_t)(sizeof(byte)*AES->block_wsize));

    byte test_value[16] = { 0xd4, 0xe0, 0xb8, 0x1e, 0xbf, 0xb4, 0x41, 0x27, 0x5d, 0x52, 0x11, 0x98, 0x30, 0xae, 0xf1, 0xe5 };

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] = test_value[i*4 + j];
        }
    }

    mix_columns(state);

    byte expected[16] = { 0x04, 0xe0, 0x48, 0x28, 0x66, 0xcb, 0xf8, 0x06, 0x81, 0x19, 0xd3, 0x26, 0xe5, 0x9a, 0x7a, 0x4c };

    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, state[0], 4);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected + 4, state[1], 4);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected + 8, state[2], 4);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected + 12, state[3], 4);

    free_2d((void **) state, state_rows);
}

void test_add_round_key() {
    byte ** state = (byte **)malloc_2d(state_rows, (size_t)(sizeof(byte)*AES->block_wsize));

    byte test_value[16] = { 0x04, 0xe0, 0x48, 0x28, 0x66, 0xcb, 0xf8, 0x06, 0x81, 0x19, 0xd3, 0x26, 0xe5, 0x9a, 0x7a, 0x4c };

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] = test_value[i*4 + j];
        }
    }

    word key[4] = { 0xa0fafe17, 0x88542cb1, 0x23a33939, 0x2a6c7605 }; 

    add_round_key(state, (word *) key);

    byte expected[16] = { 0xa4, 0x68, 0x6b, 0x02, 0x9c, 0x9f, 0x5b, 0x6a, 0x7f, 0x35, 0xea, 0x50, 0xf2, 0x2b, 0x43, 0x49 };

    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, state[0], 4);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected + 4, state[1], 4);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected + 8, state[2], 4);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected + 12, state[3], 4);

    free_2d((void **) state, state_rows);
}

void test_r_con() {
    word expected[10] = { 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000 };

    for (int i = 4; i < 44; i = i + 4) {
        TEST_ASSERT_EQUAL_UINT32(expected[i/4 - 1], r_con(i/AES->key_length));
    }
}

void test_rot_word() {
    word test[10] = { 0x09cf4f3c, 0x2a6c7605, 0x7359f67f, 0x6d7a883b, 0xdb0bad00, 0x11f915bc, 0xca0093fd, 0x4ea6dc4f, 0x7f8d292f, 0x575c006e };

    word expected[10] = { 0xcf4f3c09, 0x6c76052a, 0x59f67f73, 0x7a883b6d, 0x0bad00db, 0xf915bc11, 0x0093fdca, 0xa6dc4f4e, 0x8d292f7f, 0x5c006e57 };

    for (int i = 0; i < 10; i++) {
        test[i] = rot_word(test[i]);
    }

    TEST_ASSERT_EQUAL_UINT32_ARRAY(expected, test, 10);
}

void test_key_expansion() {
    byte key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };

    word * w = malloc(AES->key_length * (AES->rounds + 1) * sizeof(word));

    key_expansion(key, w);
    word expected[44] = { 0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c, 0xa0fafe17, 0x88542cb1, 0x23a33939, 0x2a6c7605, 0xf2c295f2, 0x7a96b943, 0x5935807a, 0x7359f67f, 0x3d80477d, 0x4716fe3e, 0x1e237e44, 0x6d7a883b, 0xef44a541, 0xa8525b7f, 0xb671253b, 0xdb0bad00, 0xd4d1c6f8, 0x7c839d87, 0xcaf2b8bc, 0x11f915bc, 0x6d88a37a, 0x110b3efd, 0xdbf98641, 0xca0093fd, 0x4e54f70e, 0x5f5fc9f3, 0x84a64fb2, 0x4ea6dc4f, 0xead27321, 0xb58dbad2, 0x312bf560, 0x7f8d292f, 0xac7766f3, 0x19fadc21, 0x28d12941, 0x575c006e, 0xd014f9a8, 0xc9ee2589, 0xe13f0cc8, 0xb6630ca6 };

    TEST_ASSERT_EQUAL_UINT32_ARRAY(expected, w, 44);
}

void test_inv_shift_rows() {
    byte ** state = (byte **)malloc_2d(state_rows, (size_t)(sizeof(byte)*AES->block_wsize));

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] = j + i*4;
        }
    }

    inv_shift_rows(state);

    byte expected1[4] = { 0, 1, 2, 3 };
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected1, state[0], 4);
    byte expected2[4] = { 7, 4, 5, 6 };
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected2, state[1], 4);
    byte expected3[4] = { 10, 11, 8, 9 };
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected3, state[2], 4);
    byte expected4[4] = { 13, 14, 15, 12 };
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected4, state[3], 4);

    free_2d((void **) state, state_rows);
}

void test_inv_sub_bytes() {
    byte ** state = (byte **)malloc_2d(state_rows, (size_t)(sizeof(byte)*AES->block_wsize));

    byte el = 0xFF;
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] = el;
            el = el << 1;
        }
    }

    sub_bytes(state);
    inv_sub_bytes(state);
    TEST_ASSERT_EQUAL_UINT8(0xFF, state[0][0]);
    TEST_ASSERT_EQUAL_UINT8(0xFE, state[0][1]);
    TEST_ASSERT_EQUAL_UINT8(0x00, state[3][3]);
    TEST_ASSERT_EQUAL_UINT8(0xF0, state[1][0]);

    free_2d((void **) state, state_rows);
}

void test_inv_mix_columns() {
    byte ** state = (byte **)malloc_2d(state_rows, (size_t)(sizeof(byte)*AES->block_wsize));

    byte test_value[16] = { 0xd4, 0xe0, 0xb8, 0x1e, 0xbf, 0xb4, 0x41, 0x27, 0x5d, 0x52, 0x11, 0x98, 0x30, 0xae, 0xf1, 0xe5 };

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] = test_value[i*4 + j];
        }
    }

    mix_columns(state);
    inv_mix_columns(state);


    TEST_ASSERT_EQUAL_UINT8_ARRAY(test_value, state[0], 4);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(test_value + 4, state[1], 4);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(test_value + 8, state[2], 4);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(test_value + 12, state[3], 4);

    free_2d((void **) state, state_rows);

}

void test_cipher() {
    byte key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    byte block[16] = { 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };
    byte expected[16] = { 0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32 };
    byte out[16];
    word * w = malloc(AES->block_wsize * (AES->rounds + 1) * sizeof(word));

    key_expansion(key, w);

    cipher(block, out, w);

    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, out, 16);
}

void test_inv_cipher() {
    byte key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    byte block[16] = { 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };
    byte out[16];
    byte res[16];
    word * w = malloc(AES->block_wsize * (AES->rounds + 1) * sizeof(word));

    key_expansion(key, w);

    cipher(block, out, w);
    inv_cipher(out, res, w);

    TEST_ASSERT_EQUAL_UINT8_ARRAY(block, res, 16);
}

void test_add_cbc_padding() {
    byte block[16];

    for (int i = 0; i < 12; i++) {
        block[i] = i;
    }

    add_cbc_padding(block, 12);

    byte expected[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 4, 4, 4, 4 };

    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, block, 16);
}

void test_del_cbc_padding() {
    byte block[16];

    for (int i = 0; i < 12; i++) {
        block[i] = i;
    }

    add_cbc_padding(block, 12);
    size_t len = del_cbc_padding(block);

    byte expected[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };

    TEST_ASSERT_EQUAL_UINT32(4, len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, block, 12);
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_sub_bytes);
    RUN_TEST(test_sub_word);
    RUN_TEST(test_shift_rows);
    RUN_TEST(test_mix_columns);
    RUN_TEST(test_add_round_key);
    RUN_TEST(test_r_con);
    RUN_TEST(test_rot_word);
    RUN_TEST(test_key_expansion);
    RUN_TEST(test_inv_shift_rows);
    RUN_TEST(test_inv_sub_bytes);
    RUN_TEST(test_inv_mix_columns);
    RUN_TEST(test_cipher);
    RUN_TEST(test_inv_cipher);
    RUN_TEST(test_add_cbc_padding);
    RUN_TEST(test_del_cbc_padding);

    return UNITY_END();
}
