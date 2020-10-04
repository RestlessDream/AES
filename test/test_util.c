#include "unity.h"
#include "../src/util.h"

void setUp(void) {
}

void tearDown(void) {
}

void test_malloc_2d() {
    int ** res = (int **)malloc_2d(1000u, sizeof(int)*1000u);

    TEST_ASSERT_NOT_NULL(res);

    for (int i = 0; i < 1000; i++) {
        for (int j = 0; j < 1000; j++) {
            res[i][j] = i + j;
        }
    }

    free_2d((void **)res, 1000);
}

void test_high_bits() {
    TEST_ASSERT_EQUAL_UINT8(0, high_bits(0x0F));
    TEST_ASSERT_EQUAL_UINT8(0xF, high_bits(0xF0));
    TEST_ASSERT_EQUAL_UINT8(0xF, high_bits(0xFF));
    TEST_ASSERT_EQUAL_UINT8(0x2, high_bits(0x22));
}

void test_low_bits() {
    TEST_ASSERT_EQUAL_UINT8(0x0F, low_bits(0x0F));
    TEST_ASSERT_EQUAL_UINT8(0x00, low_bits(0xF0));
    TEST_ASSERT_EQUAL_UINT8(0x0F, low_bits(0xFF));
    TEST_ASSERT_EQUAL_UINT8(0x02, low_bits(0x22));
}

void test_shift() {
    byte tested[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    byte expected1[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};

    shift(1, tested, 10);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected1, tested, 10);

    byte expected2[10] = {4, 5, 6, 7, 8, 9, 0, 1, 2, 3};
    shift(3, tested, 10);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected2, tested, 10);
}

void test_right_shift() {
    byte tested[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    byte expected1[10] = {9, 0, 1, 2, 3, 4, 5, 6, 7, 8};

    right_shift(1, tested, 10);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected1, tested, 10);

    byte expected2[10] = {6, 7, 8, 9, 0, 1, 2, 3, 4, 5};
    right_shift(3, tested, 10);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected2, tested, 10);
}

void test_copy_column() {
    byte ** matrix = (byte **)malloc_2d(4, sizeof(byte)*4);

    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++) {
            matrix[i][j] = i*4 + j;
        }

    byte dest[4];

    copy_column(matrix, dest, 4, 0);

    byte expected[4] = {0, 4, 8, 12};
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, dest, 4);

    copy_column(matrix, dest, 4, 1);

    byte expected1[4] = {1, 5, 9, 13};
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected1, dest, 4);

    copy_column(matrix, dest, 4, 2);

    byte expected2[4] = {2, 6, 10, 14};
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected2, dest, 4);

    copy_column(matrix, dest, 4, 3);

    byte expected3[4] = {3, 7, 11, 15};
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected3, dest, 4);

    free_2d((void **)matrix, 4);
}

void test_copy_to_column() {
    byte ** matrix = (byte **)malloc_2d(4, sizeof(byte)*4);

    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++) {
            matrix[i][j] = i*4 + j;
        }

    byte src[4] = { 113, 114, 115, 116 };

    copy_to_column(src, matrix, 4, 0);
    copy_to_column(src, matrix, 4, 2);

    byte expected[4] = {113, 1, 113, 3};
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, matrix[0], 4);

    byte expected2[4] = {114, 5, 114, 7};
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected2, matrix[1], 4);

    byte expected3[4] = {115, 9, 115, 11};
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected3, matrix[2], 4);

    byte expected4[4] = {116, 13, 116, 15};
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected4, matrix[3], 4);

    free_2d((void **)matrix, 4);
}

void test_mul_bytes() {
    TEST_ASSERT_EQUAL_UINT8(0xC1, mul_bytes(0x57, 0x83));
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_shift);
    RUN_TEST(test_right_shift);
    RUN_TEST(test_copy_column);
    RUN_TEST(test_copy_to_column);
    RUN_TEST(test_mul_bytes);
    RUN_TEST(test_malloc_2d);
    RUN_TEST(test_high_bits);
    RUN_TEST(test_low_bits);
    return UNITY_END();
}
