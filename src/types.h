#ifndef _TYPES_H_
#define _TYPES_H_

#include "stdlib.h"
#include "stdint.h"

typedef unsigned char byte;
typedef uint32_t word;
typedef void (*operation)(byte *, byte *, word*);

enum operation_t { ENCRYPT, DECRYPT };

typedef struct {
    const size_t key_length;
    const size_t block_wsize;
    const size_t rounds;
} standart_config;

#endif // TYPES_H_
