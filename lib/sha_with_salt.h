#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h> //include -lcrypto in gcc
#include <openssl/sha.h>

void print_hex(unsigned char *hash, int len);

int generate_rand_num(int min, int max);

int pbkdf2(char *passwd, unsigned char *ciphertext, int ciphertext_len, unsigned char *salt, int salt_len);

// encrypt masterkey with pbkdf2
int masterkey_init();

// @brief confirms masterkey and saves it in [masterkey]
int authenticate(char *masterkey);
