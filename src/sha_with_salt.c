#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h> //include -lcrypto in gcc
#include <openssl/evp.h>
#include <time.h>
#include "../lib/sha_with_salt.h"

void print_hex(unsigned char *hash, int len) {
	for (int i=0;i<len;i++) {
		printf("%02x ", hash[i]);
	}
	printf("\n\n");
}

int generate_rand_num(int min, int max) {
	// what if instead of scaling the random number, I just cut the last n digits from the generated random number off and just add the rest into it?
	int len = 4;
	unsigned char bytes[len];
	if (RAND_bytes(bytes, len) != 1) {
		printf("Error generating random bytes");
		exit(EXIT_FAILURE);
	}

	// convert array into a concatenated set of bits
	unsigned int num = (unsigned int)bytes[len-1];
	for (int i=1;i<len;i++) {
		num = num | ((unsigned int)bytes[i] << i*4);
	}

	// scale number to given range
	return min + (num % (max - min +1));
}

int sha256(char *passwd, char *ciphertext, int ciphertext_len) {
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	// generate salt with passwd -- maybe through a simpler sha hash?
	char salt[] = "Hello World\n";
	unsigned char md_value[EVP_MAX_MD_SIZE];
	int md_len, i;

	OpenSSL_add_all_digests();
	md = EVP_sha256();
	if(!md) {
		printf("Unknown message digest\n");
		exit(1);
	}
	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, passwd, strlen(passwd));
	EVP_DigestUpdate(mdctx, salt, strlen(salt));
	EVP_DigestFinal_ex(mdctx, md_value, &md_len);
	EVP_MD_CTX_destroy(mdctx);
	md_value[md_len] = '\0';

	if (md_len > ciphertext_len){
		perror("OPENSLL: ciphertext array is too small");
		return 1;
	}

	printf("%d long Digest in array %d long SHA256 is: ", strlen(md_value), sizeof(md_value));
	for(i = 0; i < md_len; i++)
		printf("%02x", md_value[i]);
	printf("\n");

	strcpy(ciphertext, md_value);

	/* Call this once before exit. */
	EVP_cleanup();

	return 0;
}

int pbkdf2(char *passwd, unsigned char *ciphertext, int ciphertext_len, char *salt, int salt_len) {
	int passwd_len = strlen(passwd);

	// leverage security with user experience. 1000000 iterations take roughly 1.13 seconds on my laptop
	PKCS5_PBKDF2_HMAC(passwd, passwd_len, salt, salt_len, 1000000, EVP_sha512(), ciphertext_len, ciphertext);

	printf("PBKDF2 Digest: ");
	for(int i = 0; i < ciphertext_len; i++)
		printf("%02x", ciphertext[i]);
	printf("\n");

	EVP_cleanup();
	return 0;
}

/*
int main() {
	clock_t start_time = clock();
	char ciphertext[EVP_MAX_MD_SIZE];
	char *salt = "saltsalt";
	int salt_len = 8;

	//sha512("cookie", ciphertext, EVP_MAX_MD_SIZE);
	pbkdf2("cookie", ciphertext, EVP_MAX_MD_SIZE, salt, salt_len);

	clock_t end_time = clock();
	double time_taken = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
	printf("Time taken for PBKDF2 with 5000 iterations: %f seconds\n", time_taken);

	return 0;
}
*/
