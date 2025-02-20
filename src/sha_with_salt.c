#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h> //include -lcrypto in gcc
#include <openssl/evp.h>
#include <time.h>
#include "../lib/sha_with_salt.h"
#include "../lib/log_tools.h"

#define MAX_PASSWD_LEN 100

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

int pbkdf2(char *passwd, unsigned char *ciphertext, int ciphertext_len, unsigned char *salt, int salt_len) {
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

int masterkey_init() {
	char masterkey[MAX_PASSWD_LEN] = {0};
	int salt_len = 16;
	unsigned char salt[16] = {0};

	printf("Enter new masterkey: ");
	if (fgets(masterkey, sizeof(masterkey), stdin) == NULL) {
		perror("\nInvalid Input\n");
		return 1;
	}
	masterkey[strcspn(masterkey, "\n")] = '\0'; // Replace '\n' with '\0'
	printf("\n");

	if (RAND_bytes(salt, 16) != 1) {
		printf("OPENSSL: Error generating random bytes");
		exit(EXIT_FAILURE);
	}

	unsigned char ciphertext[EVP_MAX_MD_SIZE] = {0};
	pbkdf2(masterkey, ciphertext, EVP_MAX_MD_SIZE, salt, salt_len);

	FILE *fptr = fopen("masterkey.txt", "w");
	if (fptr == NULL) {
		perror("Error opening file");
		return 1;
	}

	fprint_to_hex(fptr, salt, 16);
	write_delimiter(fptr);
	fprint_to_hex(fptr, ciphertext, EVP_MAX_MD_SIZE);

	fclose(fptr);

	return 0;
}

int authenticate(char *masterkey) {
	int attempts = 5;
	int hexsalt_len = 16 * 2;
	int hexciphertext_len = EVP_MAX_MD_SIZE * 2;
	char hexciphertext_user[EVP_MAX_MD_SIZE * 2 + 1] = {0}; // * 2 for hex format
	unsigned char ciphertext_user[EVP_MAX_MD_SIZE + 1] = {0}; // * 2 for hex format
	char hexciphertext_file[EVP_MAX_MD_SIZE * 2 + 1] = {0};
	char hex_salt[16 * 2] = {0};
	unsigned char salt[16] = {0};
	char log_buf[(EVP_MAX_MD_SIZE + 16) * 2 + 1] = {0}; // + salt len + null
	char *tmp;

	FILE *fptr = fopen("masterkey.txt", "r");
	if (fptr == NULL) {
		perror("Failed to open masterkey.txt\nHave you tried initializing with -i?\n");
		exit(EXIT_FAILURE);
	}

	if (fgets(log_buf, hexciphertext_len + hexsalt_len + 2, fptr) == NULL) { // extract whole string from masterkey.txt
		perror("failed to get masterkey hash");
		exit(EXIT_FAILURE);
	}
	fclose(fptr);

	for (attempts=5;attempts != 0;attempts--) {
		printf("Enter masterkey: ");
		if (fgets(masterkey, MAX_PASSWD_LEN, stdin) == NULL) { // get user input
			printf("\nInvalid input\n");
			continue;
		}
		masterkey[strcspn(masterkey, "\n")] = '\0'; // Replace '\n' with '\0'
		printf("\n");

		tmp = strstr((char*)log_buf, "$"); // jump to next delimiter
		memcpy(hex_salt, log_buf, tmp - log_buf); // extract salt hex
		tmp++; // skip delimiter
		strncpy(hexciphertext_file, tmp, hexciphertext_len); // extract masterkey hex

		hex_to_bytes((char*)hex_salt, hexsalt_len, salt);

		// hash masterkey and compare with masterkey hash log
		pbkdf2(masterkey, ciphertext_user, hexciphertext_len/2, salt, 16);
		bytes_to_hex(ciphertext_user, EVP_MAX_MD_SIZE, hexciphertext_user); // TODO: EVP_MAX_MD_SIZE is somehow 64 - why?

		if (!memcmp(hexciphertext_file, hexciphertext_user, hexciphertext_len)) {
			printf("masterkey confirmed\n==================================================\n\n");
			return 0;
		}

		printf("Remaining attempts: %d\n", attempts);
		memset(hexciphertext_user, 0, EVP_MAX_MD_SIZE * 2 + 1); // * 2 for hex format
		memset(ciphertext_user, 0, EVP_MAX_MD_SIZE + 1); // * 2 for hex format
		memset(hexciphertext_file, 0, EVP_MAX_MD_SIZE * 2 + 1);
		memset(salt, 0, 16);
	}

	perror("Exceeded failed attempts.\n");
	exit(EXIT_FAILURE);

	return 1;
}
