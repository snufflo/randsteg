#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include "../lib/aes.h"

// This is a source code that has been slightly modified
// ORIGINAL SOURCE CODE: https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
// can encrypt plain text with without regarding its size
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
		perror("failed to load context");
		exit(EXIT_FAILURE);
	}

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
		perror("AES: fail");
		exit(EXIT_FAILURE);
	}

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
		perror("AES UPDATE: fail");
		exit(EXIT_FAILURE);
	}
        // handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
	 * Pads the plaintext if it is not a product of 128 bits long
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
		perror("AES FINAL: fail");
		exit(EXIT_FAILURE);
	}
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;
	ERR_load_crypto_strings();

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
		perror("EVP_CIPHER_CTX_new() fail");
		exit(EXIT_FAILURE);
        // handleErrors();
	}

	//EVP_CIPHER_CTX_set_padding(ctx, 0);
    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
		perror("EVP_DecryptInit_ex() fail");
		exit(EXIT_FAILURE);
        // handleErrors();
	}

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
		perror("EVP_DecryptUpdate() fail");
		exit(EXIT_FAILURE);
        // handleErrors();
	}
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
		ERR_print_errors_fp(stderr);
		perror("EVP_DecryptFinal_ex() fail");
		exit(EXIT_FAILURE);
        // handleErrors();
	}
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}
