#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <png.h>
#include "../lib/hash_table.h"
#include <openssl/crypto.h>
// might be overlapping with libs in encryption.h
#include "../lib/aes.h"
#include <math.h>
// gotta include this in encrypted
#include "../lib/sha_with_salt.h"
#include "../lib/png_tools.h"
#include "../lib/log_tools.h"

#define MAX_ID_LEN 50
#define MAX_PASSWD_LEN 100

struct png_log {
	char *passwd_id;
	int multiplier;
	int max_digits;
	unsigned char *encrypted_coor;
	unsigned char *iv_passwd;
	unsigned char *iv_coor;
};

struct png_info {
	int width;
	int height;
	png_bytep *row;
};

void fprint_to_hex(FILE *fptr, unsigned char *buf, int buf_len) {
	for (int i=0;i<buf_len;i++) {
		if (buf[i] == 0) {
			break;
		}
		fprintf(fptr, "%02x", buf[i]);
	}
}

void bytes_to_hex(unsigned char *buf, int buf_len, unsigned char *hex) {
	for (int i=0;i<buf_len;i++) {
		if (buf[i] == 0) {
			break;
		}
		sprintf(hex + (i * 2), "%02x", buf[i]);
	}
}

void hex_to_bytes(const char *hex, unsigned char *output) {
	size_t hex_len = strlen(hex);

	if (hex_len % 2 != 0) {
		fprintf(stderr, "Invalid hex string: must have an even length.\n");
		exit(EXIT_FAILURE);
	
	}
	int output_len = hex_len / 2;
	
	for (size_t i = 0; i < output_len; i++) {
		sscanf(hex + (i * 2), "%2hhx", &output[i]);
	}
}

int calc_16_mult(int len) {
	int multiplier = 0;
	while (len >= 16) {
		len -= 16;
		multiplier++;
	}

	return multiplier;
}

/* ----------------------------------------
 * IN ORDER THE INJECTED PASSWORD-HASH TO BE UNDETECTABLE AS POSSIBLE, 
 * USE A PHOTO WITH LOTS OF RANDOMIZED NOISE
 * ----------------------------------------
*/

// Finds how many digits the larger number between width and height has
// more efficient method is possible, but png files typically don't exceed 10.000 pixels so this procedure won't take long
int how_many_digits(int width, int height) {
	int max_px = 0;
	int digits = 1;

	if (width > height) {
		max_px = width;
	}
	max_px = height;

	while (max_px >= 10) {
		max_px /= 10;
		digits++;
	}

	return digits;
}

// @brief writes the values padded with '0's until max_digits has been written for one part of coordinate
//
// @param pad pre allocated array where the padded values are added
// @param row, column: coordinates of pixels
// @param max_digits number of digits that the highest element in row or column has
// @param len length of a row or column array
void pad_coor(unsigned char *pad, int *row, int *column, int max_digits, int len) {
	// TODO: FIX ITERATION COUNT
	unsigned char *tmp = pad;

	for (int i=0;i<len;i++) {
		for (int j=1;row[i] * pow(10, j) < pow(10, max_digits);j++) {
			if (row[i] == 0) { // to prevent endless loop
				memcpy(pad, "0000", 4);
				pad += 4;
				break;
			}
			*pad = '0';
			pad++;
		}
		pad += sprintf(pad, "%d", row[i]);
		// print row[i] to file right next to it

		for (int j=1;column[i] * pow(10, j) < pow(10, max_digits);j++) {
			// print '0' to file right next to it
			if (column[i] == 0) {
				memcpy(pad, "0000", 4);
				pad += 4;
				break;
			}
			*pad = '0';
			pad++;
		}
		pad += sprintf(pad, "%d", column[i]);
		// print column[i] to file right next to it
	}
	pad = tmp;
}

/* @brief converts padded string into integers and saves it to row and column
 *
 * @param pad padded content
 * @poram row, column pre allocated array where the unpadded values are to be added
 * @param max_digits number of digits that the highest element in row or column has
 */
void unpad_coor(unsigned char *pad, int *row, int *column, int max_digits, int len) {
	char *coor = malloc(max_digits + 1);

	for (int i=0;i < len;i++) {
		// unpad row
		memcpy(coor, pad, max_digits);
		coor[max_digits+1] = '\0';
		pad += max_digits;

		row[i] = atoi(coor);

		//unpad column
		memcpy(coor, pad, max_digits);
		coor[max_digits+1] = '\0';
		pad += max_digits;

		column[i] = atoi(coor);
	}
}

void distribute_bits(const char *filepath, struct png_info *png, char *hash, int *c_row, int *c_column) {
	HashTable *table = create_table();
	// one char is 8bits long and we want to distribute the bits in each pixel coordinates
	int tmp_depth;
	unsigned char tmp_bit;
	int n = 0;

	if (c_row == NULL || c_column == NULL) {
		perror("Error allocating memory for c_row or c_column");
		exit(EXIT_FAILURE);
	}

	// distribute bits of passwd into the png byte array
	for (int i=0;i<strlen(hash);i++) {
		for (int j=0;j<8;) {
			n = j + 8 * i;
			tmp_bit = 0;
			// set target (j+1)-th bit from i-th-hash-byte
			tmp_bit = (hash[i] >> j) & 1;

			tmp_depth = generate_rand_num(0, 3);
			c_row[n] = generate_rand_num(0, png->height - 1);
			// each pixel has 4 bytes and each row arrays in png_bytep has column * 4 arrays each with 4 pixel channels
			c_column[n] = generate_rand_num(0, png->width - 1);

			// if generated numbers don't overlap with previous values
			if (!search(table, c_row[n], c_column[n], tmp_depth)) {
				insert(table, c_row[n], c_column[n], tmp_depth);

				// add the bit to the target pixel:
				// set offset to the given RGB or A channel
				int pixel_offset = c_column[n] * 4 + tmp_depth;

				png_bytep row = png->row[c_row[n]]; // get row pointer
				// 0xFE in binary: 11111110
				row[pixel_offset] = (row[pixel_offset] & 0xFE) | (tmp_bit & 1);

				// only iterate when the if condition is true
				j++;
			}
		}
	}

	FILE *png_fptr = fopen(filepath, "w");
	if (png_fptr == NULL) {
		perror("Error opening png file for writing");
		exit(EXIT_FAILURE);
	}

	// write manipulated pixels into png
	// TODO: custom name of file in argv
	write_png("stegged.png", png->row, png->width, png->height);
	fclose(png_fptr);

}
// struct of **coordinates: [row] [column] [RGB or A] [depth of bit]
void steg_in_png(const char *filepath, char *passwd_id, unsigned char *passwd, unsigned char *masterkey) {
	struct png_info png;
	struct png_log png_log;
	unsigned char passwd_hash[EVP_MAX_MD_SIZE + 1] = {0};
	int *c_row;
	int *c_column;

	// read png into row and get width and height
	read_png(filepath, &png.row, &png.width, &png.height);

	png_log.iv_passwd = calloc(17, sizeof(char));
	png_log.iv_coor = calloc(17, sizeof(char));
	if (png_log.iv_coor == NULL || png_log.iv_passwd == NULL) {
		perror("CALLOC: png_log iv");
		exit(EXIT_FAILURE);
	}

	// generate random iv and encrypt passwd with masterkey
	RAND_bytes(png_log.iv_passwd, 16);
	encrypt(passwd, strlen(passwd), masterkey, png_log.iv_passwd, passwd_hash);

	int bits_in_hash = (int)strlen(passwd_hash) * 8; // one char = 8 bits long
	c_row = calloc(bits_in_hash, sizeof(int));
	c_column = calloc(bits_in_hash, sizeof(int));
	// 	this prevents endless looping
	if ((png.width * png.height * 4) / 2 < bits_in_hash) {
		perror("png file is too small for password\n");
		exit(EXIT_FAILURE);
	}

	distribute_bits(filepath, &png, passwd_hash, c_row, c_column);

	// Format: passwd_id $ multipliert_16 $ max_digits $ encrypted_coordinates $ iv_passwd $ iv_coor
	// 16, because aes works in 16 byte block operations
	FILE *log_fptr = fopen("log.txt", "r+");
	if (log_fptr == NULL) {
		log_fptr = fopen("log.txt", "w");
		if (log_fptr == NULL) {
			perror("Error opening log file");
			exit(EXIT_FAILURE);
		}
	}
	
	//-------------preparations for logfile---------------
	
	// pad coordinates with 0s for logging
	png_log.max_digits = how_many_digits(png.width, png.height);
	int size_of_padded = bits_in_hash * 2 * png_log.max_digits;

	png_log.multiplier = calc_16_mult(size_of_padded);
	if (png_log.multiplier <= 0) {
		perror("multiplier == 0");
		exit(EXIT_FAILURE);
	}
	int coor_ciphertext_len = png_log.multiplier * 16 * png_log.max_digits * 2;
	png_log.encrypted_coor = calloc(coor_ciphertext_len, sizeof(char));
	unsigned char *padded = calloc(size_of_padded, sizeof(char));

	RAND_bytes(png_log.iv_coor, 16);
	pad_coor(padded, c_row, c_column, png_log.max_digits, bits_in_hash);

	coor_ciphertext_len = encrypt(padded, size_of_padded, masterkey, png_log.iv_coor, png_log.encrypted_coor);

	//--------logfile write operations----------

	// write passwd_id and '$'
	if (fwrite(passwd_id, sizeof(char), strlen(passwd_id), log_fptr) != strlen(passwd_id)) {
		perror("Error writing passwd_id to log.txt");
		exit(EXIT_FAILURE); // might need to delete the string then...
	}
	write_delimiter(log_fptr);

	// write multiplier of 16
	fprintf(log_fptr, "%d", png_log.multiplier);
	write_delimiter(log_fptr);

	fprintf(log_fptr, "%d", png_log.max_digits);
	write_delimiter(log_fptr);

	// write encrypted_coordinate and '$'
	fprint_to_hex(log_fptr, png_log.encrypted_coor, coor_ciphertext_len);
	write_delimiter(log_fptr);

	// write iv and '$'
	fprint_to_hex(log_fptr, png_log.iv_passwd, 16);
	write_delimiter(log_fptr);

	// write encrypted_coordinate and '$'
	fprint_to_hex(log_fptr, png_log.iv_coor, 16);

	if (fwrite("\n", sizeof(char), 1, log_fptr) != 1) {
		perror("Error writing new line to log.txt");
		exit(EXIT_FAILURE);
	}

	fclose(log_fptr);

	free(padded);
	free(png_log.encrypted_coor);
	free(png_log.iv_passwd);
	free(png_log.iv_coor);
	free(c_row);
	free(c_column);
}

unsigned int tokenize_log(struct png_log *png_log, char *passwd_id) {
	char chr = 0;
	int int_chr = 0;
	FILE *fptr_log = fopen("log.txt", "r");
	if (fptr_log == NULL) {
		perror("failed to open log.txt");
		goto clean_up;
	}

	// find correct password id
	while (int_chr != EOF) {
		int status = parse_log(fptr_log, png_log->passwd_id, MAX_ID_LEN, 0);
		if (status == 2) {
			perror("length of array is too small for log value");
			goto clean_up;
		}

		if (strcmp(png_log->passwd_id, passwd_id) == 0) {
			// success
			int_chr = getc(fptr_log); // skip delimiter
			break;
		}

		// go to new line
		while (chr != '\n' || int_chr != EOF) {
			int_chr = getc(fptr_log);
			if (int_chr == EOF) { // if EOF is detected
				perror("Invalid password id");
				goto clean_up;
			}
			chr = (char)int_chr;
		}

	}
	// fptr should be in the right line now
	
	// TODO: with upper process, fptr is past the first delimiter -> parsing integer 1 and 2 might be incorrect!
	png_log->multiplier = parse_integer(fptr_log, 4, 1);

	png_log->max_digits = parse_integer(fptr_log, 10, 2);

	// gotta use a multiple of 16 bytes, because aes operates in 16 byte blocks
	// the length of padded coordinates are 
	// 2 (width and height per pixel) * 8 (bits per byte) * x (multiplier for 16) * 16 (block operation for aes)
	int encrypted_coor_len = 2 * 8 * png_log->multiplier * 16;
	png_log->encrypted_coor = calloc(encrypted_coor_len, sizeof(char));
	if (png_log->encrypted_coor == NULL) {
		perror("CALLOC: png_log->encrypted_coor");
		goto clean_up;
	}
	png_log->iv_passwd = calloc(17, sizeof(char));
	png_log->iv_coor = calloc(17, sizeof(char));
	if (png_log->iv_passwd == NULL || png_log->iv_coor) {
		perror("CALLOC: png_log iv");
		goto clean_up;
	}

	parse_log(fptr_log, png_log->encrypted_coor, encrypted_coor_len, 3);
	parse_log(fptr_log, png_log->iv_passwd, 17, 4);
	parse_log(fptr_log, png_log->iv_coor, 17, 5);

	fclose(fptr_log);

	return encrypted_coor_len;

clean_up:
	fclose(fptr_log);
	exit(EXIT_FAILURE);
}

// @brief searches for passwd_id in log file and decrypts encrypted coordinates with masterkey, extracts the bits and saves it to passwd
int decrypt_steg(char *passwd_id, unsigned char *masterkey, char *filepath, unsigned char *passwd) {
	// TODO: WHAT ABOUT THE MULTIPLIER??? GOTTA DO SMTH WITH THAT
	struct png_log png_log;
	unsigned int decrypted_len;
	png_log.passwd_id = calloc(MAX_ID_LEN, sizeof(unsigned char));
	png_log.iv_coor = calloc(17, sizeof(unsigned char));
	png_log.iv_passwd = calloc(17, sizeof(unsigned char));

	unsigned int encrypted_hexcoor_len = tokenize_log(&png_log, passwd_id);
	unsigned int encrypted_coor_len = encrypted_hexcoor_len/2;

	// decrypted coor must be at least the len of encrypted coor (to be safe)
	unsigned char *padded_coor = calloc(encrypted_coor_len + 1, sizeof(unsigned char));
	unsigned char *encrypted_coor = calloc(encrypted_coor_len + 1, sizeof(unsigned char)); // hex -> binary, hex is represented with two chars, so byte is half as long
	unsigned char *hex_encrypted_coor = calloc(encrypted_hexcoor_len + 1, sizeof(unsigned char));

	// convert hex data from log into original bytes
	hex_to_bytes(hex_encrypted_coor, encrypted_coor);
	free(hex_encrypted_coor);
	hex_encrypted_coor = NULL;

	// decrypt original bytes
	decrypted_len = decrypt(png_log.encrypted_coor, encrypted_hexcoor_len, masterkey, png_log.iv_coor, padded_coor);

	unsigned int pixel_num = (encrypted_coor_len / png_log.max_digits) / 2;
	free(padded_coor);
	padded_coor = NULL;

	// initialize png_bytep with pixel_num
	int *row = malloc(pixel_num * sizeof(int));
	int *column = malloc(pixel_num * sizeof(int));

	// un-pad the values and save them as integers in row and column arrays
	unpad_coor(padded_coor, row, column, png_log.max_digits, pixel_num);
	
	struct png_info png;
	read_png(filepath, &png.row, &png.width, &png.height);

	unsigned char *passwd_hash = calloc(pixel_num/8, sizeof(unsigned char));
	if (passwd_hash == NULL) {
		perror("Error allocating array space");
		return NULL;
	}
	unsigned char bit;
	
	// extract targeted bits from pixels
	for (int i=0;i<pixel_num/8;i++) {
		for (int j=0;j<8;j++) {
			// extract the target bit 
			bit = png.row[row[i*8 + j]][column[i*8 + j]] & 1;
			// add extracted bit to passwd[i]
			passwd_hash[i] |= (bit << j);
		}
	}

	decrypt(passwd_hash, pixel_num/8, masterkey, png_log.iv_passwd, passwd);

	return 0;
}

// encrypt masterkey with pbkdf2
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

// @brief confirms masterkey and saves it in [masterkey]
int authenticate(char *masterkey) {
	int attempts = 5;
	int hexsalt_len = 16 * 2;
	int hexciphertext_len = EVP_MAX_MD_SIZE * 2;
	unsigned char hexciphertext_user[EVP_MAX_MD_SIZE * 2 + 1] = {0}; // * 2 for hex format
	unsigned char ciphertext_user[EVP_MAX_MD_SIZE + 1] = {0}; // * 2 for hex format
	unsigned char hexciphertext_file[EVP_MAX_MD_SIZE * 2 + 1] = {0};
	unsigned char hex_salt[16 * 2] = {0};
	unsigned char salt[16] = {0};
	unsigned char log_buf[(EVP_MAX_MD_SIZE + 16) * 2 + 1] = {0}; // + salt len + null
	unsigned char *tmp;

	FILE *fptr = fopen("masterkey.txt", "r");
	if (fptr == NULL) {
		perror("Failed to open masterkey.txt\nHave you tried initializing with -i?\n");
		exit(EXIT_FAILURE);
	}

	// extract whole string from masterkey.txt
	if (fgets(log_buf, hexciphertext_len + hexsalt_len + 2, fptr) == NULL) {
		perror("failed to get masterkey hash");
		exit(EXIT_FAILURE);
	}
	fclose(fptr);

	for (attempts=5;attempts != 0;attempts--) {
		// get user input
		printf("Enter masterkey: ");
		if (fgets(masterkey, sizeof(masterkey), stdin) == NULL) {
			printf("\nInvalid input\n");
			continue;
		}
		masterkey[strcspn(masterkey, "\n")] = '\0'; // Replace '\n' with '\0'
		printf("\n");

		tmp = strstr(log_buf, "$");
		memcpy(hex_salt, log_buf, tmp - log_buf); // extract salt hex
		tmp++; // skip delimiter
		strncpy(hexciphertext_file, tmp, hexciphertext_len); // extract masterkey hex
														  //
		hex_to_bytes(hex_salt, salt);

		// hash masterkey and compare with masterkey hash log
		pbkdf2(masterkey, ciphertext_user, hexciphertext_len/2, salt, 16);
		bytes_to_hex(ciphertext_user, EVP_MAX_MD_SIZE, hexciphertext_user);

		if (!memcmp(hexciphertext_file, hexciphertext_user, hexciphertext_len)) {
			printf("masterkey confirmed\n");
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

void get_usrinput_steg(char *passwd_id, char *passwd, char *masterkey) {
	printf("Enter id of password: ");
	if (!fgets(passwd_id, 100, stdin)) {
		perror("FGETS: error");
		exit(EXIT_FAILURE);
	}
	passwd_id[strcspn(passwd_id, "\n")] = '\0'; // Replace '\n' with '\0'
	printf("\n");

	printf("Enter password you want to hide: ");
	if (!fgets(passwd, MAX_PASSWD_LEN, stdin)) {
		perror("FGETS: error");
		exit(EXIT_FAILURE);
	}
	passwd[strcspn(passwd, "\n")] = '\0';
	printf("\n");

	printf("Enter your masterkey: ");
	if (!fgets(masterkey, MAX_PASSWD_LEN, stdin)) {
		perror("FGETS: error");
		exit(EXIT_FAILURE);
	}
	masterkey[strcspn(masterkey, "\n")] = '\0';
	printf("\n");
}

int main(int argc, char *argv[]) {
	/*
	---Example of accessing row array for reference---
	png_bytep *rowp = NULL;
	const char *input_file = "cheese.png";
	int width, height;
	
	read_png(input_file, &rowp, &width, &height);
	printf("%d\n", height);

	png_bytep row = rowp[400];
	for (int i=0;i<width;i++) {
		png_bytep px = &(row[i * 4]); // access i-th pixel: each pixel is 4bytes long and each array element is 1byte long
		printf("%d %d %d %d\n", px[0], px[1], px[2], px[3]);
	}

	const char *output_file = "new.png";
	write_png(output_file, rowp, width, height);
	*/

	if (argc == 4) {
		if (strncmp(argv[1], "-d", 2) == 0) { // extract bits and decrypt password
			printf("option: decrypt detected\n");
			char passwd[MAX_PASSWD_LEN] = {0};
			char masterkey[MAX_PASSWD_LEN] = {0};

			authenticate(masterkey);

			decrypt_steg(argv[2], argv[3], masterkey, passwd);

			printf("Password: %s", passwd);
		}
		else {
			printf("Invalid option\n");
			exit(EXIT_FAILURE);
		}
	}
	else if (argc == 2) {
		if (strncmp(argv[1], "-i", 2) == 0) { // initialize masterkey
			printf("option: init detected\n");
			masterkey_init();
			return 0;
		}
		else if (strncmp(argv[1], "-h", 2) == 0) { // display help
			printf("Thank you for using randsteg! \n\n Options and Format: \n");
			printf("'randsteg -d PASSWD_ID FILEPATH_TO_PNG'\n\t- Exstracts and decrypts the password for [PASSWD_ID] that is in [FILEPATH_TO_PNG]\n\n");
			printf("'randsteg FILEPATH_TO_PNG'\n\t- Encrypts and hides password into FILEPATH_TO_PNG\n\n");
			return 0;
		}
		else if (strncmp(argv[1], "--test", 2) == 0) {
			unsigned char byte[50] = {0};
			unsigned char cipher[EVP_MAX_MD_SIZE] = {0};
			unsigned char salt[] = "12345";
			unsigned char key[] = "keyyyy";

			RAND_bytes(byte, 50);
			int cipher_len = encrypt(byte, 50, key, salt, cipher);

			for (int i=0;i<cipher_len;i++) {
				printf("%02x", cipher[i]);
			}

			return 0;
		}
		else { // inject password bits into png
			printf("option: injection detected\n");
			char passwd[MAX_PASSWD_LEN + 1] = {0};
			char passwd_id[100] = {0};
			char masterkey[MAX_PASSWD_LEN + 1] = {0};

			get_usrinput_steg(passwd_id, passwd, masterkey);

			steg_in_png(argv[1], passwd_id, passwd, masterkey);
		}

	}
	else {
		perror("Invalid command. Type 'randsteg -h' for more information\n");
		exit(EXIT_FAILURE);
	}
	return 0;
}
