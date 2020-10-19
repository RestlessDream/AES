#include "modes.h"

#include "aes.h"
#include "util.h"
#include <string.h>
#include <stdio.h>

extern const size_t block_bsize;

static byte buf_[BLOCK_BSIZE];
static byte * prev_;
static byte alpha = 0x8F;
static size_t cicle;
static size_t bsize = BLOCK_BSIZE;

/**
 * Block cipher mode of operation initialization
 * @param iv - initialization vector
 * @param mode - block cipher mode
 */
void init(byte * iv, enum bc_mode mode) {
    if (mode == CTR) {
        memset(buf_, 0, block_bsize/2);
        memcpy(buf_ + block_bsize/2, iv, block_bsize/2);
        prev_ = buf_;
    } else {
        prev_ = iv;
    }

    cicle = 0;
}

/**
 * Electoric codebook mode realization
 *
 * Every block is encrypted separately.
 *
 * @param in - input stream (plaintext/ciphertext)
 * @param out - output stream (ciphertext/plaintext)
 * @param w - expanded key
 * @param op - operation function (cipher/inv_cipher)
 * @param op_t - operation type (encyption/decryption)
 */
void ecb_mode(byte * in, byte * out, word * w, operation op,
                enum operation_t op_t) {
    op(in, out, w);
}

/**
 * Cipher block chaining
 *
 * Input of next block xored with output of previous.
 *
 * @param in - input stream (plaintext/ciphertext)
 * @param out - output stream (ciphertext/plaintext)
 * @param w - expanded key
 * @param op - operation function (cipher/inv_cipher)
 * @param op_t - operation type (encyption/decryption)
 */
void cbc_mode(byte * in, byte * out, word * w, operation op,
                enum operation_t op_t) {
    if (op_t == ENCRYPT) {
        xor_arr(in, in, prev_, block_bsize);

        op(in, out, w);

        prev_ = out;
    } else {
        op(in, out, w);

        xor_arr(out, out, prev_, block_bsize);

        prev_ = in;
    }
}

/**
 * Propagation Cipher block chaining
 *
 * Input of next block xored with xored value of output and input of previous.
 *
 * @param in - input stream (plaintext/ciphertext)
 * @param out - output stream (ciphertext/plaintext)
 * @param w - expanded key
 * @param op - operation function (cipher/inv_cipher)
 * @param op_t - operation type (encyption/decryption)
 */
void pcbc_mode(byte * in, byte * out, word * w, operation op,
                enum operation_t op_t) {

    if (op_t == ENCRYPT) {
        memcpy(buf_, in, block_bsize);
        xor_arr(in, in, prev_, block_bsize);

        op(in, out, w);

        xor_arr(buf_, buf_, out, block_bsize);

        prev_ = buf_;
    } else {
        op(in, out, w);

        xor_arr(out, out, prev_, block_bsize);

        xor_arr(buf_, in, out, block_bsize);

        prev_ = buf_;
    }
}

/**
 * Cipher feedback
 *
 * Initial vector gets encrypted than xored with input.
 * After every previous output gets encrypted and xored with input. 
 *
 * @param in - input stream (plaintext/ciphertext)
 * @param out - output stream (ciphertext/plaintext)
 * @param w - expanded key
 * @param op - operation function (cipher/inv_cipher)
 * @param op_t - operation type (encyption/decryption)
 */
void cfb_mode(byte * in, byte * out, word * w, operation op,
                enum operation_t op_t) {
    if (op_t == ENCRYPT) {
        op(prev_, out, w);
        xor_arr(out, in, out, block_bsize);

        prev_ = out;
    } else {
        op(prev_, out, w);
        xor_arr(out, in, out, block_bsize);

        prev_ = in;
    }
}

/**
 * Output feedback
 *
 * Initial vector gets encrypted than xored with input.
 * After every previous encrypted block gets encrypted and xored with input. 
 *
 * @param in - input stream (plaintext/ciphertext)
 * @param out - output stream (ciphertext/plaintext)
 * @param w - expanded key
 * @param op - operation function (cipher/inv_cipher)
 * @param op_t - operation type (encyption/decryption)
 */
void ofb_mode(byte * in, byte * out, word * w, operation op,
                enum operation_t op_t) {
    op(prev_, out, w);
    memcpy(buf_, out, block_bsize);
    xor_arr(out, in, out, block_bsize);

    prev_ = buf_;
}

/**
 * Counter
 *
 * Initial vector defined as concatination of nonce and counter = {...000}.
 * Initial vector gets encrypted and xored with plaintext.
 * At the end of every call IV gets incremented.
 *
 * @param in - input stream (plaintext/ciphertext)
 * @param out - output stream (ciphertext/plaintext)
 * @param w - expanded key
 * @param op - operation function (cipher/inv_cipher)
 * @param op_t - operation type (encyption/decryption)
 */
void ctr_mode(byte * in, byte * out, word * w, operation op,
                enum operation_t op_t) {
    op(prev_, out, w);
    xor_arr(out, in, out, block_bsize);
    ((uint64_t *)buf_)[0]++;
    prev_ = buf_;
}

/**
 * XEX-based tweaked-codebook mode with ciphertext stealing (XTS)
 *
 * @param in - input stream (plaintext/ciphertext)
 * @param out - output stream (ciphertext/plaintext)
 * @param w - expanded key
 * @param op - operation function (cipher/inv_cipher)
 * @param op_t - operation type (encyption/decryption)
 */
void xts_mode(byte * in, byte * out, word * w, operation op,
                enum operation_t op_t) {
    if (cicle == 0) {
        memcpy(buf_, prev_, block_bsize);
        prev_ = buf_;
        op(prev_, prev_, w);
        cicle++;
    } else {
        mul_bytes_128(prev_, alpha);
    }

    if (bsize == BLOCK_BSIZE) {
        xor_arr(in, in, prev_, block_bsize);
        op(in, out, w);
        xor_arr(out, out, prev_, block_bsize);
    } else {
        byte buf2[BLOCK_BSIZE];
        memcpy(buf2, in, bsize);
        memcpy(buf2 + (block_bsize - bsize), out - (block_bsize - bsize),
                    block_bsize - bsize); 

        memcpy(out, out - block_bsize, bsize);
        
        xor_arr(buf2, buf2, prev_, block_bsize);
        op(buf2, out - block_bsize, w);
        xor_arr(out - block_bsize, out - block_bsize, prev_, block_bsize);
    }
}
