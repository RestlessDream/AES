#include "aes.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

extern standart_config AES_128;
extern standart_config AES_192;
extern standart_config AES_256;
extern size_t state_rows;
extern size_t block_bsize;
const size_t BUFFER_SIZE = 64 * 1024;

typedef void (*operation)(byte *, byte *, word*);
size_t hexs2bin(const char *hex, unsigned char **out);
int hexchr2bin(const char hex, char * out);

int parse_arguments(int argc, char ** argv, FILE ** input, FILE ** output, byte * key, bool * op,
        standart_config * standart, bool * cbc_padding);

int main(int argc, char ** argv) {
    FILE * input;
    FILE * output;
    byte key[32];
    bool op_ = true;
    operation op;
    standart_config * AES = &AES_128;
    bool cbc_padding = false;
    
    if (parse_arguments(argc, argv, &input, &output, key, &op_, AES, &cbc_padding) != 0) {
        return 1;
    }

    if (op_) {
        op = &cipher;
    } else {
        op = &inv_cipher;
    }

    setup(AES);
    word * w = malloc(AES->block_wsize * (AES->rounds + 1) * sizeof(word));
    key_expansion(key, w);

    byte * rbuffer = malloc(BUFFER_SIZE * sizeof(byte));
    byte * wbuffer = malloc(BUFFER_SIZE * sizeof(byte));

    size_t reads;
    size_t before_r = 0;
    size_t read_blocks;
    while ((reads = fread(rbuffer, sizeof(byte), BUFFER_SIZE, input)) != 0) {
        read_blocks = reads / block_bsize;

        for (size_t i = 0; i < read_blocks; i++) {
            op(rbuffer + block_bsize * i, wbuffer + block_bsize * i, w);
        }

        if (reads % block_bsize != 0) {
            if (!op_) {
                fprintf(stderr, "Corrupted file.");

                return -1;
            }

            if (cbc_padding) {
                add_cbc_padding(rbuffer + block_bsize * read_blocks,
                        reads % block_bsize);
                reads = (read_blocks + 1) * block_bsize;
            } else {
                memset(rbuffer + block_bsize * read_blocks + reads % block_bsize,
                        0x0, block_bsize - reads % block_bsize);
                reads = (read_blocks + 1) * block_bsize;
            }

            op(rbuffer + read_blocks * block_bsize, wbuffer + read_blocks * block_bsize, w);
        }

        if (reads < BUFFER_SIZE && !op_ && cbc_padding) {
            reads -= del_cbc_padding(wbuffer + reads - block_bsize);
        }

        if (fwrite(wbuffer, sizeof(byte), reads, output) == 0) {
            fprintf(stderr, "Error occured while writting to the output file.");
            return -1;
        }

        before_r = reads;
    }

    if (!op_ && before_r == BUFFER_SIZE && reads == 0 && cbc_padding) {
        fseek(output, 0L, SEEK_END);
        long sz = ftell(output);

        sz -= del_cbc_padding(wbuffer + before_r - block_bsize);

        if (ftruncate(fileno(output), sz) != 0) {
            fprintf(stderr, "File truncate error.");

            return -3;
        }
    }

    free(rbuffer);
    free(wbuffer);
    free(w);
    fclose(input);
    fclose(output);

    return 0;
}

int parse_arguments(int argc, char ** argv, FILE ** input, FILE ** output, byte * key, bool * op,
        standart_config * standart, bool * cbc_padding) {
    int option;
    size_t key_len;
    int is_all = 0;

    while ((option = getopt(argc, argv, "i:o:k:eds:ph")) != -1) {
        switch (option) {
            case 'i':
                *input = fopen(optarg, "r");
                is_all++;
                break;
            case 'o':
                *output = fopen(optarg, "w+");
                is_all++;
                break;
            case 'k':
                key_len = hexs2bin(optarg, &key);
                is_all++;
                break;
            case 'e':
                *op = true;
                break;
            case 'd':
                *op = false;
                break;
            case 's':
                if (strcmp(optarg, "AES128") == 0) {
                    standart = &AES_128;
                } else if (strcmp(optarg, "AES192") == 0) {
                    standart = &AES_192;
                } else if (strcmp(optarg, "AES256") == 0) {
                    standart = &AES_256;
                } else {
                    fprintf(stderr, "%s wrong standart name, looks -h for supported standarts.\n", optarg);
                    return -1;
                }

                break;
            case 'p':
                *cbc_padding = true;
                break;
            case '?':
                fprintf(stderr, "%s unsuported flag.", optarg);

                return -2;
            case 'h':
                printf("Usage:  aes -i file_path -o file_path -k key [options]\n\n\
AES standart decryption\\encyption.\n\
Options:\n\
  -i    Input file path.\n\
  -o    Output file path.\n\
  -e    Encrypt operation. Encrypt by default.\n\
  -k    Given key.\n\
  -d    Decrypt operation.\n\
  -s    Standart name. Allowed options: AES128, AES192, AES256.\n\
  -p    Use CBC padding.\n\
  -h    display this help.\n");

                return 1;
        }
    }

    if (is_all < 3) {
        fprintf(stderr, "Needs to satisfy all parameters, use -h for help.\n");

        return -3;
    }

    if (key_len != standart->key_length * sizeof(word)) {
        fprintf(stderr, "Key lenght is not standart compliant.\n");

        return -4;
    }

    return 0;
}

size_t hexs2bin(const char *hex, unsigned char **out) {
	size_t len;
	char   b1;
	char   b2;
	size_t i;

	if (hex == NULL || *hex == '\0' || out == NULL)
		return 0;

	len = strlen(hex);
	if (len % 2 != 0)
		return 0;
	len /= 2;

	memset(*out, 'A', len);
	for (i=0; i<len; i++) {
		if (!hexchr2bin(hex[i*2], &b1) || !hexchr2bin(hex[i*2+1], &b2)) {
			return 0;
		}
		(*out)[i] = (b1 << 4) | b2;
	}
	return len;
}

int hexchr2bin(const char hex, char *out) {
	if (out == NULL)
		return 0;

	if (hex >= '0' && hex <= '9') {
		*out = hex - '0';
	} else if (hex >= 'A' && hex <= 'F') {
		*out = hex - 'A' + 10;
	} else if (hex >= 'a' && hex <= 'f') {
		*out = hex - 'a' + 10;
	} else {
		return 0;
	}

	return 1;
}
