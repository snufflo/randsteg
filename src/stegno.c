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

int hex_to_bytes(const char *hex, int hex_len, unsigned char *output) {
	int chrs = 0;

	if (hex_len % 2 != 0) {
		fprintf(stderr, "Invalid hex string: must have an even length.\n");
		exit(EXIT_FAILURE);
	
	}
	int output_len = hex_len / 2;
	
	for (size_t i = 0; i < output_len; i++) {
		chrs++;
		sscanf(hex + (i * 2), "%2hhx", &output[i]);
	}

	return chrs;
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
void pad_coor(unsigned char *pad, int *row, int *column, int *depth, int max_digits, int len) {
	unsigned char *tmp = pad;

	for (int i=0;i<len;i++) {
		for (int j=1;row[i] * pow(10, j) < pow(10, max_digits);j++) {
			if (row[i] == 0) { // to prevent endless loop
				memset(pad, '0', max_digits-1); //-1, because row[i] will be added later
				pad += max_digits-1;
				break;
			}
			*pad = '0';
			pad++;
		}
		pad += sprintf(pad, "%d", row[i]); // print row[i] to file right next to it

		for (int j=1;column[i] * pow(10, j) < pow(10, max_digits);j++) {
			// print '0' to file right next to it
			if (column[i] == 0) {
				memset(pad, '0', max_digits-1);
				pad += max_digits-1;
				break;
			}
			*pad = '0';
			pad++;
		}
		pad += sprintf(pad, "%d", column[i]); // print column[i] to file right next to it
		
		for (int j=1;depth[i] * pow(10, j) < pow(10, max_digits);j++) {
			if (depth[i] == 0) {
				memset(pad, '0', max_digits-1);
				pad += max_digits-1;
				break;
			}
			*pad = '0';
			pad++;
		}
		pad += sprintf(pad, "%d", depth[i]); // print column[i] to file right next to it
	}
	pad = tmp;
}

/* @brief converts padded string into integers and saves it to row and column
 *
 * @param pad padded content
 * @poram row, column pre allocated array where the unpadded values are to be added
 * @param max_digits number of digits that the highest element in row or column has
 */
void unpad_coor(unsigned char *pad, int *row, int *column, int *depth, int max_digits, int len) {
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

		//unpad depth
		memcpy(coor, pad, max_digits);
		coor[max_digits+1] = '\0';
		pad += max_digits;

		depth[i] = atoi(coor);
	}
}

void distribute_bits(const char *filepath, struct png_info *png, char *hash, int hash_len, int *c_row, int *c_column, int *depth) {
	HashTable *table = create_table();
	int tmp_depth;
	unsigned char tmp_bit;
	int n = 0;
	int pixel_offset = 0;

	for (int i=0;i<strlen(hash);i++) { // distribute bits of passwd into the png byte array
		for (int j=0;j<8;) {
			n = j + 8 * i; // each pixel has 4 bytes and each row arrays in png_bytep has column * 4 arrays each with 4 pixel channels
			tmp_bit = (hash[i] >> j) & 1; // set target (j+1)-th bit from i-th-hash-byte

			depth[n] = generate_rand_num(0, 3);
			c_row[n] = generate_rand_num(0, png->height - 1); 
			c_column[n] = generate_rand_num(0, png->width - 1);

			if (!search(table, c_row[n], c_column[n], depth[n])) { // if generated numbers don't overlap with previous values
				insert(table, c_row[n], c_column[n], depth[n]);

				// add the bit to the target pixel:
				// set offset to the given RGB or A channel
				pixel_offset = c_column[n] * 4 + depth[n];

				png_bytep row = png->row[c_row[n]]; // get row pointer
				row[pixel_offset] = (row[pixel_offset] & 0xFE) | (tmp_bit & 1); // 0xFE in binary: 11111110

				j++; // only iterate when the if condition is true
			}
		}
	}

	FILE *png_fptr = fopen(filepath, "w");
	if (png_fptr == NULL) {
		perror("Error opening png file for writing");
		exit(EXIT_FAILURE);
	}

	// TODO: custom name of file in argv
	write_png("stegged.png", png->row, png->width, png->height); // write manipulated pixels into png
	fclose(png_fptr);

}
// struct of **coordinates: [row] [column] [RGB or A] [depth of bit]
void steg_in_png(const char *filepath, char *passwd_id, unsigned char *passwd, unsigned char *masterkey) {
	struct png_info png;
	struct png_log png_log;
	unsigned char passwd_hash[EVP_MAX_MD_SIZE] = {0};
	unsigned char masterkey_hash[32] = {0};
	int ciphertext_len = 0;
	int *c_row;
	int *c_column;
	int *depth;

	read_png(filepath, &png.row, &png.width, &png.height); // read png into row and get width and height

	png_log.iv_passwd = calloc(16, sizeof(char));
	png_log.iv_coor = calloc(16, sizeof(char));
	if (png_log.iv_coor == NULL || png_log.iv_passwd == NULL) {
		perror("CALLOC: png_log iv");
		exit(EXIT_FAILURE);
	}

	// CAUTION: aes can output a nullterminator in the middle of the ciphertext!
	// CAUTION: if aes_256s input is a multiple of 16, it adds ANOTHER 16 BYTES TO IT
	// generate random iv and encrypt passwd with masterkey
	RAND_bytes(png_log.iv_passwd, 16);
	pbkdf2(masterkey, masterkey_hash, 32, png_log.iv_passwd, 16);
	ciphertext_len = encrypt(passwd, strlen(passwd), masterkey_hash, png_log.iv_passwd, passwd_hash);

	int bits_in_hash = ciphertext_len * 8; // one char = 8 bits long
	c_row = calloc(bits_in_hash, sizeof(int));
	c_column = calloc(bits_in_hash, sizeof(int));
	depth = calloc(bits_in_hash, sizeof(int));
	
	if ((png.width * png.height * 4) / 2 < bits_in_hash) { // this prevents endless looping when inserting randomly generate coordinates to hashtable later
		perror("png file is too small for password\n");
		exit(EXIT_FAILURE);
	}

	distribute_bits(filepath, &png, passwd_hash, ciphertext_len, c_row, c_column, depth);

	// Format: passwd_id $ multiplier_16 $ max_digits $ encrypted_coordinates $ iv_passwd $ iv_coor
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
	
	png_log.max_digits = how_many_digits(png.width, png.height); 
	// 
	int size_of_padded = bits_in_hash * 3 * png_log.max_digits; // bits_in_hash includes 8 (bits) and times 2 always is a multiple of 16

	png_log.multiplier = size_of_padded/16;
	if (png_log.multiplier <= 0) {
		perror("multiplier == 0");
		exit(EXIT_FAILURE);
	}
	// additional 32 bytes for safety
	int coor_ciphertext_len = png_log.multiplier * 16 * png_log.max_digits * 3 + 32;
	png_log.encrypted_coor = calloc(coor_ciphertext_len, sizeof(char));
	unsigned char *padded = calloc(size_of_padded, sizeof(char));

	pad_coor(padded, c_row, c_column, depth, png_log.max_digits, bits_in_hash);

	RAND_bytes(png_log.iv_coor, 16);
	pbkdf2(masterkey, masterkey_hash, 32, png_log.iv_coor, 16);
	// size_of_padded is a multiple of 16 -> AES ADDS ADDITIONAL 16 BYTES AFTER
	coor_ciphertext_len = encrypt(padded, size_of_padded, masterkey_hash, png_log.iv_coor, png_log.encrypted_coor);

	png_log.multiplier = coor_ciphertext_len/16; // calculate again, because aes might have added padding
	if (png_log.multiplier <= 0) {
		perror("multiplier == 0");
		exit(EXIT_FAILURE);
	}
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

	// write iv_passwd and '$'
	fprint_to_hex(log_fptr, png_log.iv_passwd, 16);
	write_delimiter(log_fptr);

	// write iv_coor
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

	while (int_chr != EOF) { // find correct password id
		int status = parse_log(fptr_log, png_log->passwd_id, MAX_ID_LEN, 0);
		if (status == 2) {
			perror("length of array is too small for log value");
			goto clean_up;
		}

		if (strcmp(png_log->passwd_id, passwd_id) == 0) { // success
			int_chr = getc(fptr_log); // skip delimiter
			break;
		}

		while (chr != '\n' || int_chr != EOF) { // go to new line
			int_chr = getc(fptr_log);
			if (int_chr == EOF) { // if EOF is detected
				perror("Invalid password id");
				goto clean_up;
			}
			chr = (char)int_chr;
		}

	} // fptr should be in the right line now
	
	png_log->multiplier = parse_integer(fptr_log, 4, 1);
	png_log->max_digits = parse_integer(fptr_log, 10, 2);

	// gotta use a multiple of 16 bytes, because aes operates in 16 byte blocks
	// the length of padded coordinates are 
	// 2 (width and height per pixel) * 8 (bits per byte) * x (multiplier for 16) * 16 (block operation for aes)
	int encrypted_coor_len = png_log->multiplier * 16;
	png_log->encrypted_coor = calloc(encrypted_coor_len, sizeof(unsigned char));
	if (png_log->encrypted_coor == NULL) {
		perror("CALLOC: png_log->encrypted_coor");
		goto clean_up;
	}
	
	int hexencrypted_coor_len = encrypted_coor_len * 2;
	char *hexencrypted_coor = calloc(hexencrypted_coor_len, sizeof(char)); 
	if (hexencrypted_coor == NULL) {
		perror("CALLOC: hexencrypted_coor");
		goto clean_up;
	}
	char hex_iv_passwd[16*2] = {0};
	char hex_iv_coor[16*2] = {0};

	parse_log(fptr_log, hexencrypted_coor, hexencrypted_coor_len, 3);
	parse_log(fptr_log, hex_iv_passwd, 16*2, 4);
	parse_log(fptr_log, hex_iv_coor, 16*2, 5);

	int hex_len = hex_to_bytes(hexencrypted_coor, hexencrypted_coor_len, png_log->encrypted_coor);
	printf("decoded hex len: %d", hex_len);

	hex_to_bytes(hex_iv_passwd, 16*2, png_log->iv_passwd);
	hex_to_bytes(hex_iv_coor, 16*2, png_log->iv_coor);

	fclose(fptr_log);
	free(hexencrypted_coor);
	hexencrypted_coor = NULL;

	return encrypted_coor_len;

clean_up:
	fclose(fptr_log);
	exit(EXIT_FAILURE);
}

// @brief searches for passwd_id in log file and decrypts encrypted coordinates with masterkey, extracts the bits and saves it to passwd
int decrypt_steg(char *passwd_id, unsigned char *masterkey, char *filepath, unsigned char *passwd) {
	struct png_log png_log;
	unsigned int decrypted_len;
	unsigned char masterkey_hash[32] = {0};
	png_log.passwd_id = calloc(MAX_ID_LEN, sizeof(unsigned char));
	png_log.iv_coor = calloc(16, sizeof(unsigned char));
	png_log.iv_passwd = calloc(16, sizeof(unsigned char));
	unsigned int encrypted_coor_len = tokenize_log(&png_log, passwd_id);
	unsigned char *padded_coor = calloc(encrypted_coor_len * 3, sizeof(unsigned char)); // decrypted coor must be at least the len of encrypted coor (to be safe)

	pbkdf2(masterkey, masterkey_hash, 32, png_log.iv_coor, 16);
	decrypted_len = decrypt(png_log.encrypted_coor, encrypted_coor_len, masterkey_hash, png_log.iv_coor, padded_coor); // decrypt original bytes 
	printf("padded coordinates: %s", padded_coor);

	unsigned int pixel_num = (decrypted_len / png_log.max_digits) / 3; // TODO: check if this is correct 
	// initialize png_bytep with pixel_num
	unsigned int *row = calloc(pixel_num, sizeof(int));
	unsigned int *column = calloc(pixel_num, sizeof(int));
	unsigned int *depth = calloc(pixel_num, sizeof(int));

	unpad_coor(padded_coor, row, column, depth, png_log.max_digits, pixel_num); // un-pad the values and save them as integers in row and column arrays
	
	struct png_info png;
	read_png(filepath, &png.row, &png.width, &png.height);

	unsigned char *passwd_hash = calloc(pixel_num/8, sizeof(unsigned char));
	if (passwd_hash == NULL) {
		perror("Error allocating array space");
		return 1;
	}

	unsigned char bit = 0;
	unsigned int pixel_offset = 0;
	unsigned int n = 0;
	// TODO: this isn't right. fix
	for (int i=0;i<pixel_num/8;i++) { // extract targeted bits from pixels
		for (int j=0;j<8;j++) {
			n = i * 8 + j; // calc index of pixel
			pixel_offset = column[n] * 4 + depth[n];
			
			bit = png.row[row[n]][pixel_offset] & 1; // extract the target bit 
			passwd_hash[i] |= (bit << j); // add extracted bit to passwd[i]
		}
	}

	pbkdf2(masterkey, masterkey_hash, 32, png_log.iv_passwd, 16);
	decrypt(passwd_hash, pixel_num/8, masterkey_hash, png_log.iv_passwd, passwd);

	free(padded_coor);
	padded_coor = NULL;

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

	if (fgets(log_buf, hexciphertext_len + hexsalt_len + 2, fptr) == NULL) { // extract whole string from masterkey.txt
		perror("failed to get masterkey hash");
		exit(EXIT_FAILURE);
	}
	fclose(fptr);

	for (attempts=5;attempts != 0;attempts--) {
		printf("Enter masterkey: ");
		if (fgets(masterkey, sizeof(masterkey), stdin) == NULL) { // get user input
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
		hex_to_bytes(hex_salt, hexsalt_len, salt);

		// hash masterkey and compare with masterkey hash log
		pbkdf2(masterkey, ciphertext_user, hexciphertext_len/2, salt, 16);
		bytes_to_hex(ciphertext_user, EVP_MAX_MD_SIZE, hexciphertext_user); // TODO: EVP_MAX_MD_SIZE is somehow 64 - why?

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

			decrypt_steg(argv[2], masterkey, argv[3], passwd);

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
			unsigned char cipher_hex[EVP_MAX_MD_SIZE * 2 + 64] = {0};
			unsigned char salt[16];
			unsigned char key[32];
			unsigned char byte_hex[50 * 2];

			unsigned char passwd_id[MAX_ID_LEN];
			unsigned char passwd[MAX_PASSWD_LEN];
			unsigned char masterkey[MAX_PASSWD_LEN];
			unsigned char cipher_pad[EVP_MAX_MD_SIZE];
			unsigned char pad[20] = {0};

			unsigned int *row = calloc(3, sizeof(unsigned char));
			unsigned int *column = calloc(3, sizeof(unsigned char));

			for (int i=0; i<3; i++) {
				row[i] = i*5;
				column[i] = i*5;
			}
			//pad_coor(pad, row, column, 3, 3);

			get_usrinput_steg(passwd_id, passwd, masterkey);
			RAND_bytes(salt, 16);

			printf("original: %s", pad);
			printf("\n");
			
			pbkdf2(masterkey, key, 32, salt, 16);
			int cipher_len = encrypt(pad, strlen(pad), key, salt, cipher_pad);

			printf("cipher_hex: %s", cipher_hex);
			printf("\n");
			FILE *fptr = fopen("test.txt", "w");
			fprint_to_hex(fptr, cipher_pad, cipher_len); // this might be the problem: you have to use cipher_len
			fprintf(fptr, "\n");
			fclose(fptr);

			memset(pad, 0, 17);
			memset(cipher_hex, 0, EVP_MAX_MD_SIZE * 2 + 64);
			memset(cipher_pad, 0, EVP_MAX_MD_SIZE);
			memset(masterkey, 0, MAX_PASSWD_LEN);
			memset(key, 0, 32);
			FILE *fptr_r = fopen("test.txt", "r");
			char chr;

			for(int i=0;i<EVP_MAX_MD_SIZE + 64;i++) {
				chr = (char)fgetc(fptr_r);
				if (chr == '\n')
					break;
				memcpy(cipher_hex+i, &chr, 1);
			}
			hex_to_bytes(cipher_hex, EVP_MAX_MD_SIZE*2, cipher_pad); // this might be the problem: incorrect length of hex

			get_usrinput_steg(passwd_id, passwd, masterkey);
			pbkdf2(masterkey, key, 32, salt, 16);

			decrypt(cipher_pad, cipher_len, key, salt, pad);
			printf("decrypted: %s", pad);

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
