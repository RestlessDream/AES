#ifndef _AES_H_
#define _AES_H_

#include "static.h"

void setup(standart_config * AES_standart);
void cipher(byte * in, byte * out, word * w);
void sub_bytes(byte ** state);
word sub_word(word value);
void shift_rows(byte ** state);
void mix_columns(byte ** state);
void mix_column(byte * clmn);
void add_round_key(byte ** state, word * w);
void key_expansion(byte * key, word * w);

word r_con(size_t index);
word rot_word(word value);
word ctime(word w);

void inv_cipher(byte * in, byte * out, word * w);

void inv_shift_rows(byte ** state);
void inv_sub_bytes(byte ** state);
void inv_mix_columns(byte ** state);

void add_cbc_padding(byte * block, size_t size);
size_t del_cbc_padding(byte * block);

#endif // AES_H_
