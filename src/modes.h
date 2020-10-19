#ifndef MODES_H_
#define MODES_H_

#include "static.h"

enum bc_mode { ECB, CBC, PCBC, CFB, OFB, CTR, XTS }; 

void init(byte * iv, enum bc_mode mode);

typedef void (*w_mode)(byte *, byte *, word*, operation, enum operation_t);

void ecb_mode(byte * in, byte * out, word * w, operation op,
                            enum operation_t op_t);

void cbc_mode(byte * in, byte * out, word * w, operation op,
                            enum operation_t op_t);

void pcbc_mode(byte * in, byte * out, word * w, operation op,
                            enum operation_t op_t);

void cfb_mode(byte * in, byte * out, word * w, operation op,
                            enum operation_t op_t);

void ofb_mode(byte * in, byte * out, word * w, operation op,
                            enum operation_t op_t);

void ctr_mode(byte * in, byte * out, word * w, operation op,
                            enum operation_t op_t);

void xts_mode(byte * in, byte * out, word * w, operation op,
                            enum operation_t op_t);
#endif
