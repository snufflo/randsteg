#pragma once

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

// This is a source code that has been slightly modified
// ORIGINAL SOURCE CODE: https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
// can encrypt plain text with without regarding its size
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext);

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext);

void handleErrors(void);
