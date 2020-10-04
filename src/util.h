#ifndef _UTIL_H_
#define _UTIL_H_

#include "types.h"

#include "stdlib.h"

void ** malloc_2d(size_t rows, size_t elm_arr_size);
void free_2d(void ** m2d, size_t rows);
byte high_bits(byte val);
byte low_bits(byte val);
void shift(size_t r, byte * arr, size_t size);
void right_shift(size_t r, byte * arr, size_t size);
void copy_column(byte ** src, byte * dest, size_t rsize, size_t cindex);
void copy_to_column(byte * src, byte ** dest, size_t rsize, size_t cindex);
byte mul_bytes(byte a, byte b);

#endif // UTIL_H_
