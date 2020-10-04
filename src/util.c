#include "util.h"

void ** malloc_2d(size_t rows, size_t elm_arr_size) {
    void ** res = (void **) malloc(rows * sizeof(void *));

    for (size_t i = 0; i < rows; i++) {
        res[i] = malloc(elm_arr_size); 
    }

    return res;
}

void free_2d(void ** m2d, size_t rows) {
    for (size_t i = 0; i < rows; i++) {
        free(m2d[i]);
    }

    free(m2d);
}

byte high_bits(byte val) {
    return (val & 0xF0) >> 4;
}

byte low_bits(byte val) {
    return val & 0x0F;
}

void shift(size_t r, byte * arr, size_t size) {
    for (size_t i = 0; i < r; i++) {
        byte swp =  arr[0];

        for (size_t j = 0; j < size - 1; j++) {
            arr[j] = arr[j + 1];
        }

        arr[size - 1] = swp;
    }
}

void right_shift(size_t r, byte * arr, size_t size) {
    for (size_t i = 0; i < r; i++) {
        byte swp =  arr[size - 1];

        for (size_t j = size - 1; j > 0; j--) {
            arr[j] = arr[j - 1];
        }

        arr[0] = swp;
    }
}

void copy_column(byte ** src, byte * dest, size_t rsize, size_t cindex) {
    for (size_t i = 0; i < rsize; i++) {
        dest[i] = src[i][cindex];
    }
}

void copy_to_column(byte * src, byte ** dest, size_t rsize, size_t cindex) {
    for (size_t i = 0; i < rsize; i++) {
        dest[i][cindex] = src[i];
    }
}

byte mul_bytes(byte a, byte b) {
    byte res = 0;
    byte high_bit_mask = 0x80;
    byte high_bit = 0;
    byte modulo = 0x1B;

    for (int i = 0; i < 8; i++) {
        if (b & 1) {
            res ^= a;
        }

        high_bit = a & high_bit_mask;

        a <<= 1;

        if (high_bit) {
            a ^= modulo;
        }

        b >>= 1;
    }

    return res;
}
