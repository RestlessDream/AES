# AES

## Description
- *main.c* - provides a command line user interface;
- *aes.h, aes.c* - contains the main part of AES alghorithm, fully compliant to standard: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf ;
- *static.h, static.c* - contains the static part of algorithm (e.g. *s_box, standard configurations ...*);
- *types.h* - contains typedef aliases;
- *util.h, util.c* - contains utility methods (e.g. *shift, mul_bytes ...*);

### Unit tests:
- *test_aes_128.c* - AES 128 standard test set;
- *test_aes_192.c* - AES 192 standard test set;
- *test_aes_256.c* - AES 256 standard test set;
