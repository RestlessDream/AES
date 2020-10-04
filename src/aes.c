#include "aes.h"

#include "util.h"

#include "stdlib.h"
#include "string.h"

extern standart_config * AES;
extern standart_config AES_192;
extern size_t block_bsize;
extern size_t state_rows;
extern byte s_box[16][16];
extern byte inv_s_box[16][16];

void cipher(byte * in, byte * out, word * w) {
    byte ** state = (byte **) malloc_2d(state_rows, AES->block_wsize * sizeof(byte));

    for (size_t r = 0; r < state_rows; r++) {
        for (size_t c = 0; c < AES->block_wsize; c++) {
            state[r][c] = in[r + 4 * c];
        }
    }

    add_round_key(state, w);

    for (int i = 1; i < AES->rounds; i++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, w + i * AES->block_wsize);
    }

    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, w + AES->rounds * AES->block_wsize);

    for (size_t r = 0; r < state_rows; r++) {
        for (size_t c = 0; c < AES->block_wsize; c++) {
            out[r + 4 * c] = state[r][c];
        }
    }

    free_2d((void **) state, state_rows);
}

void sub_bytes(byte ** state) {
    for (size_t i = 0; i < state_rows; i++) {
        for (size_t j = 0; j < AES->block_wsize; j++) {
            state[i][j] = s_box[high_bits(state[i][j])][low_bits(state[i][j])];
        }
    }
}

word sub_word(word value) {
    byte * res = (byte *) &value;

    for (size_t i = 0; i < sizeof(word)/sizeof(byte); i++) {
        res[i] = s_box[high_bits(res[i])][low_bits(res[i])];
    }

    return *((word *) res);
}

void shift_rows(byte ** state) {
    for (size_t i = 1; i < state_rows; i++) {
        shift(i, state[i], AES->block_wsize);
    }
}

void mix_columns(byte ** state) {
    byte * tmp = malloc(state_rows * sizeof(byte));

    for (size_t i = 0; i < AES->block_wsize; i++) {
        copy_column(state, tmp, state_rows, i);

        mix_column(tmp);

        copy_to_column(tmp, state, state_rows, i);
    }

    free(tmp);
}


void mix_column(byte * clmn) {
    byte * a = malloc(state_rows * sizeof(byte));
    byte * b = malloc(state_rows * sizeof(byte));

    for (size_t i = 0; i < state_rows; i++) {
        a[i] = clmn[i];
        byte h = (byte)((signed char)clmn[i] >> 7);
        b[i] = clmn[i] << 1; 
        b[i] ^= 0x1B & h;
    }

    clmn[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1]; 
    clmn[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2];
    clmn[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3];
    clmn[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0];

    free(a);
    free(b);
}

void add_round_key(byte ** state, word * w) {
    byte * wb = (byte *) w;

    for (size_t i = 0; i < state_rows; i++) {
        for (size_t j = 0; j < AES->block_wsize; j++) {
            state[i][j] = state[i][j] ^ wb[AES->block_wsize - 1 - i + j * state_rows];
        }
    }
}

void key_expansion(byte * key, word * w) {
    word temp;

    size_t i = 0;

    for (; i < AES->key_length; i++) {
        ((byte *) w)[i*4 + 3] = key[i*4];
        ((byte *) w)[i*4 + 2] = key[i*4 + 1];
        ((byte *) w)[i*4 + 1] = key[i*4 + 2];
        ((byte *) w)[i*4] = key[i*4 + 3];
    }

    for (; i < AES->block_wsize * (AES->rounds + 1); i++) {
        temp = w[i - 1];

        if (i % AES->key_length == 0) {
            temp = sub_word(rot_word(temp)) ^ r_con(i / AES->key_length);
        } else if (AES->key_length > AES_192.key_length && i % AES->key_length == 4) {
            temp = sub_word(temp);
        }

        w[i] = w[i - AES->key_length] ^ temp;
    }
}

word r_con(size_t index) {
    word res = 1;

    for (int i = 0; i < index - 1; i++) {
        res = ctime(res);
    }

    return res << 24;
}

word rot_word(word value) {
    byte * res = (byte *) &value;

    right_shift(1, res, sizeof(word)); 

    return *((word *) res);
}


word ctime(word w) {
    return (w << 1) ^ (((w >> 7) & 1) * 0x11B);
}

void inv_cipher(byte * in, byte * out, word * w) {
    byte ** state = (byte **) malloc_2d(state_rows, AES->block_wsize * sizeof(byte));

    for (size_t r = 0; r < state_rows; r++) {
        for (size_t c = 0; c < AES->block_wsize; c++) {
            state[r][c] = in[r + 4 * c];
        }
    }

    add_round_key(state, w + AES->rounds * AES->block_wsize);

    for (int i = AES->rounds - 1; i > 0; i--) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, w + i * AES->block_wsize);
        inv_mix_columns(state);
    }

    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, w);

    for (size_t r = 0; r < state_rows; r++) {
        for (size_t c = 0; c < AES->block_wsize; c++) {
            out[r + 4 * c] = state[r][c];
        }
    }

    free_2d((void **) state, state_rows);
}

void inv_shift_rows(byte ** state) {
    for (size_t i = 1; i < state_rows; i++) {
        right_shift(i, state[i], AES->block_wsize);
    }
}

void inv_sub_bytes(byte ** state) {
    for (size_t i = 0; i < state_rows; i++) {
        for (size_t j = 0; j < AES->block_wsize; j++) {
            state[i][j] = inv_s_box[high_bits(state[i][j])][low_bits(state[i][j])];
        }
    }
}

void inv_mix_columns(byte ** state) {
    byte * a = malloc(state_rows * sizeof(byte));
    byte * b = malloc(state_rows * sizeof(byte));

    for (size_t i = 0; i < AES->block_wsize; i++) {
        for (size_t j = 0; j < state_rows; j++) {
            a[j] = state[j][i];
        }

        b[0] = mul_bytes(0x0e, a[0]) ^ mul_bytes(0x0b, a[1]) ^ mul_bytes(0x0d, a[2]) ^ mul_bytes(0x09, a[3]);
        b[1] = mul_bytes(0x09, a[0]) ^ mul_bytes(0x0e, a[1]) ^ mul_bytes(0x0b, a[2]) ^ mul_bytes(0x0d, a[3]);
        b[2] = mul_bytes(0x0d, a[0]) ^ mul_bytes(0x09, a[1]) ^ mul_bytes(0x0e, a[2]) ^ mul_bytes(0x0b, a[3]);
        b[3] = mul_bytes(0x0b, a[0]) ^ mul_bytes(0x0d, a[1]) ^ mul_bytes(0x09, a[2]) ^ mul_bytes(0x0e, a[3]);

        for (size_t j = 0; j < state_rows; j++) {
            state[j][i] = b[j];
        }
    }

    free(a);
    free(b);
}

void setup(standart_config * AES_standart) {
    AES = AES_standart;
}

void add_cbc_padding(byte * block, size_t size) {
    if (size >= block_bsize) {
        return;
    }

    byte padding_num = block_bsize - size;

    for (size_t i = size; i < block_bsize; i++) {
        block[i] = padding_num;
    }
}

size_t del_cbc_padding(byte * block) {
    byte padding_num = block[block_bsize - 1];

    if (padding_num >= block_bsize) {
        return 0;
    }

    for (int i = block_bsize - 2; i >= block_bsize - padding_num; i--) {
        if (block[i] != padding_num) {
            return 0;
        }
    }

    return padding_num;
}
