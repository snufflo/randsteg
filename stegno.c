#include <stdio.h>
#include <stdlib.h>
#include <png.h>
#include <hash_table.h>
#include <openssl/crypto.h>
// might be overlapping with libs in encryption.h
#include <aes.h>

/* ----------------------------------------
 * IN ORDER THE INJECTED PASSWORD-HASH TO BE UNDETECTABLE AS POSSIBLE, 
 * USE A PHOTO WITH LOTS OF RANDOMIZED NOISE
 * ----------------------------------------
*/
void read_png (const char *filename, png_bytep **row_pointers, int *width, int *height) {
	FILE *fp = fopen(filename, "rb");
	if (!fp) {
		perror("Failed to open PNG");
		exit(EXIT_FAILURE);
	}

	png_structp png = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
	if (!png) exit(EXIT_FAILURE);

	png_infop info = png_create_info_struct(png);
	if (!info) exit(EXIT_FAILURE);

	if (setjmp(png_jmpbuf(png))) exit(EXIT_FAILURE);

	png_init_io(png, fp);

	png_read_info(png, info);

	*width = png_get_image_width(png, info);
	*height = png_get_image_height(png, info);
	png_byte color_type = png_get_color_type(png, info);
	png_byte bit_deph = png_get_bit_depth(png, info);

	// confirm proper PNG format
	
	// set bit deph of png to 8, if bit deph == 16
	if (bit_deph == 16)
        png_set_strip_16(png);

    if (color_type == PNG_COLOR_TYPE_PALETTE)
        png_set_palette_to_rgb(png);

	// set grayscale bit deph to 8, if png color type is gray and grayscale is below 8bit
    if (color_type == PNG_COLOR_TYPE_GRAY && bit_deph < 8)
        png_set_expand_gray_1_2_4_to_8(png);

	// if png contains transparent pixels, turn them into alpha channel = 0
	// ensures wide compatibility, as lots of libs and systems use the alpha channel rather than transparency chunks
    if (png_get_valid(png, info, PNG_INFO_tRNS))
        png_set_tRNS_to_alpha(png);

	// adds an alpha channel, if the png doesnt have one already
	// FILLER_AFTER indicates where the alpha channel will be added: at the end
	// this is for extra capacity for stegnography
    if (color_type == PNG_COLOR_TYPE_RGB ||
        color_type == PNG_COLOR_TYPE_GRAY ||
        color_type == PNG_COLOR_TYPE_PALETTE)
        png_set_filler(png, 0xFF, PNG_FILLER_AFTER);

    if (color_type == PNG_COLOR_TYPE_GRAY || 
		color_type == PNG_COLOR_TYPE_GRAY_ALPHA)
        png_set_gray_to_rgb(png);

	png_read_update_info(png, info);

	// Allocate memory for row pointers
	*row_pointers = (png_bytep*)malloc(sizeof(png_bytep) * (*height));
	for(int i=0;i<*height;i++) {
		(*row_pointers)[i] = (png_byte*)malloc(png_get_rowbytes(png, info));
	}

	png_read_image(png, *row_pointers);

	fclose(fp);
	png_destroy_read_struct(&png, &info, NULL);
}

void write_png(const char *filename, png_bytep *row, int width, int height) {
	FILE *fp = fopen("stegged.png", "w");
	if (!fp) {
		perror("Failed to open png");
		exit(EXIT_FAILURE);
	}

	png_structp png = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
	if (!png) exit(EXIT_FAILURE);

	png_infop info = png_create_info_struct(png);
	if (!info) exit(EXIT_FAILURE);

	// if using libpng causes error, longjmp(png_jmpbuf(png), 1) will be executed
	// this lets the program jump to this state/"checkpoint"
	// initially, setjmp will return 0, but after the jump a non-zero value
	// TLDR: for graceful error handling 
	// (this type of low-level error handling is not typical)
	if (setjmp(png_jmpbuf(png))) exit(EXIT_FAILURE);

	// link png write struct to the file itself
	png_init_io(png, fp);

	// meta data for the png file
	png_set_IHDR(
			png,
			info,
			width, height,
			8,		// bit deph: how many bits are used to represent color info(RGBA)
			PNG_COLOR_TYPE_RGBA,
			PNG_INTERLACE_NONE,
			PNG_COMPRESSION_TYPE_DEFAULT,
			PNG_FILTER_TYPE_DEFAULT
	);
	png_write_info(png, info);

	png_write_image(png, row);
	png_write_end(png, NULL);

	fclose(fp);
	png_destroy_write_struct(&png, &info);
}

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

// writes the values padded with '0's until max_digits has been written for one part of coordinate
// pad: pre allocated array where the padded values are added
// row, column: coordinates of pixels
// max_digits: number of digits that the highest element in row or column has
// len: length of a row or column array
void pad_coor(char *pad, int *row, int *column, int max_digits, int len) {
	char *tmp = pad;

	for (int i=0;i<max_digits+1;i++) {
		for (int j=1;row[i] * pow(10, j) < pow(10, max_digits);j++) {
			*pad = '0';
			pad++;
		}
		pad += sprintf(pad, "%d", row[i]);
		// print row[i] to file right next to it

		for (int j=1;column[i] * pow(10, j) < pow(10, max_digitis);j++) {
			// print '0' to file right next to it
			*pad = '0';
			pad++;
		}
		pad += sprintf(pad, "%d", column[i]);
		// print column[i] to file right next to it
	}
	pad = tmp;
}

void write_delimiter(FILE *fptr) {
	if (fwrite("$", sizeof(char), 1, fptr) != 1) {
		perror("Error writing delimiter to log.txt");
		exit(EXIT_FAILURE);
	}
}

// struct of **coordinates: [row] [column] [RGB or A] [depth of bit]
void steg_in_png(const char *filename, char *passwd_id, char *hash_algo_id, char *hash) {
	png_bytep *row = NULL;
	int width;
	int height;
	// read png into row and get width and height
	read_png(filename, &row, &width, &height);

	// one char is 8bits long and we want to distribute the bits in each pixel coordinates
	int bits_in_hash = strlen(hash) * 8;

	// all temporary values
	int *c_row = malloc(bits_in_hash * sizeof(int));
	int *c_column = malloc(bits_in_hash * sizeof(int));
	int tmp_depth;
	char tmp_bit;
	HashTable table;

	if (c_row == NULL || c_column == NULL) {
		perror("Error allocating memory for c_row or c_column");
		exit(EXIT_FAILURE);
	}

	// TODO: check if the row is too small to distribute the bits of passwd
	// passwd bits should be less than half of the row size
	// 	- this prevents endless looping

	// distribute bits of passwd into the png byte array
	for (int i=0;i<strlen(hash);i++) {
		for (int j=0;j<8;) {
			tmp_bit = 0;
			// set target j-th bit from i-th-hash-byte
			tmp_bit = (hash[i] >> j) & 1;

			tmp_depth = generate_rand_num(0, 3);
			c_row[j] = generate_rand_num(0, width);
			c_column[j] = generate_rand_num(0, height);

			// if generated numbers don't overlap with previous values
			if (!search(table, c_row[j], c_column[j], tmp_depth)) {
				// update hash table with new values
				insert(table, c_row[j], c_column[j], tmp_depth);
				// set offset to the given RGB or A channel
				c_column[j] += tmp_depth * 4;

				// add the bit to the target pixel:
				// 0xFE in binary: 11111110
				row[c_row[j]][c_column[j]] = (row[c_row[j]][c_column[j]] & 0xFE) | tmp_bit;
				// only iterate when the if condition is true
				j++;
			}
		}
	}


	// Format: passwd_id $ hash_algo_id $ string_length $ encrypted_filepath_to_png $ string_length $ encrypted_coordinates $ max_digits
	FILE *log_fptr = fopen("log.txt", "r+");
	_Bool file_exists = 1;
	if (log_fptr == NULL) {
		log_fptr = fopen("log.txt", "w");
		if (log_fptr == NULL) {
			perror("Error opening log file");
			exit(EXIT_FAILURE);
		}
		file_exists = 0;
	}
	
	if (file_exists) {
		// TODO: find id and position file pointer to the row and column
		// with fseek() and alphabetical order of passwd category
		
		// TODO: extract the id of passwd in current line
		// determine if the entry is in alphabetical order
		// each characters are represented with bits. could it be that "higher" alphabets are represented by "higher" numbers?
		// if so, way better to search
		//
		// if in alphabetical order, move file pointer, 
		// move file pointer via binary search
		//
		// if yes, create new line, leave the if clause and continue
	}

	
	//-------------preparations for logfile---------------
	
	// !!!!!!! HARD CODED ONLY FOR TEST !!!!!!!!
    unsigned char key[] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 
		0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33,
		0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31
	};
    unsigned char iv[] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35
	};
	int coor_ciphertext_len;
	int fname_ciphertext_len;

	// ciphertext will be used for the encrypted coordinates again 
	// 960 bits is enough for 15 char that are padded with max. 4 digits
	// 15 * 8 * 4 * 2
	// so 144 bytes would be a 16 byte product
    unsigned char *coor_ciphertext = malloc(144 * sizeof(char));
	unsigned char *fname_ciphertext = malloc(144 * sizeof(char));

	fname_ciphertext_len = encrypt(filename, strlen(filename), key, iv, fname_ciphertext));

	// pad coordinates with 0s
	int max_digits = how_many_digits(width, height);
	int size_of_padded = bits_in_hash * 2 * max_digits;
	char *padded = malloc(size_of_padded * sizeof(char));
	pad_coor(padded, row, column, max_digits, bits_in_hash);

	// encrypt padded coordinates
	coor_ciphertext_len = encrypt(padded, size_of_padded, key, iv, coor_ciphertext);


	//--------logfile write operations----------//

	// write passwd_id and '$'
	if (fwrite(passwd_id, sizeof(char), strlen(passwd_id), log_fptr) != strlen(passwd_id)) {
		perror("Error writing to log.txt");
		exit(EXIT_FAILURE); // might need to delete the string then...
	}
	write_delimiter(log_fptr);

	// write hash_algo_id and '$'
	if (fwrite(hash_algo_id, sizeof(char), strlen(hash_algo_id), log_fptr) != strlen(passwd_id)) {
		perror("Error writing algorithm id to log.txt");
		exit(EXIT_FAILURE); // again, might need to delete string
	}
	write_delimiter(log_fptr);
	fprintf(log_fptr, "%d", ciphertext_len);
	write_delimiter(log_fptr);

	// write encrypted_coordinate and '$'
	if (fwrite(coor_ciphertext, sizeof(char), coor_ciphertext_len, log_fptr) != coor_ciphertext_len) {
		perror("Error writing encrypted filepath to log.txt);
		exit(EXIT_FAILURE);
	}
	write_delimiter(log_fptr);


	fprintf(log_fptr, "%d", ciphertext_len);
	write_delimiter(log_fptr);
	if (fwrite(coor_ciphertext, sizeof(char), coor_ciphertext_len, log_fptr) != coor_ciphertext_len) {
		perror("Error writing encrypted coordinates to log.txt);
	}
	write_delimiter(log_fptr);

	fprintf(log_fptr, "%d", max_digits);
	fclose(log_fptr);


	FILE *png_fptr = fopen(filename, "w");
	if (png_fptr == NULL) {
		perror("Error opening png file for writing");
		exit(EXIT_FAILURE);
	}

	// write manipulated pixels into png
	// TODO: custom name of file in argv
	write_png("stegged.png", row, width, height);
	fclose(png_fptr);

	free(padded);
	free(ciphertext);
	free(c_row);
	free(c_column);
}

// decrypts coordinates with master_passwd, extracts encrypted passwd with coordinates and decrypts the passwd
char* decrypt_steg(char *passwd_id, char *master_passwd) {
	int len_coor = /* size of coor */
	int width;
	int height;
	char bit;
	png_bytep *rowp = NULL;
	char *passwd = calloc(len_coor/8, sizeof(char));
	int decrypted_len;
	if (passwd == NULL) {
		perror("Error allocating array space");
		return NULL;
	}

	read_png(filename, rowp, &width, &height);

	// TODO: extract coordinates from filename
	FILE *fptr = fopen("log.txt", "r");
	if (fptr == NULL) {
		perror("failed to open log.txt");
		exit(EXIT_FAILURE);
	}

	// Find correct password id
	// reminder: alphabetically ordered list
	
	// extract and tokenize the whole string
	
	// !!!!!!! HARD CODED ONLY FOR TEST !!!!!!!!
    unsigned char key[] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 
		0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33,
		0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31
	};
    unsigned char iv[] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35
	};


	// decrypt coordinates and filename
	// first move file pointer to the encrypted part
	// TODO: figure out calculations for parameter
	decrypted_len = decrypt(, , key, iv, )

	// un-pad the values and save them as integers in row and column arrays
	
	// open filepath
	
	// extract bits from coordinates
	
	for (int i=0;i<len_coor/8;i++) {
		for (int j=0;j<8;j++) {
			// extract the target bit 
			bit = rowp[width][height] & 1;
			// add extracted bit to passwd[i]
			passwd[i] |= (bit << j);
		}
	}

	return passwd;
}

int authenticate(char *masterkey) {
	int num;

	if (fgets(masterkey, sizeof(masterkey), stdin) != NULL) {
		// hash masterkey and compare with masterkey hash log
		FILE *fptr = fopen("masterkey.txt", "r");
		if (fptr == NULL) {
			prinft("Failed to open masterkey.txt\nHave you tried initializing with -i?\n");
		}

		// TODO: decryption with aes
	}
	else {
		printf("Incorrect Password");
	}
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

	if (argc > 2) {

		if (strncmp(argv[1], "-d") == 0) {
			int attempts = 5;
			for (;attempts>0;attempts++) {
				char *masterkey = malloc(100 * sizeof(char));
				if (authenticate(masterkey) == 1) {
					break;
				}
				printf("Remaining attempts: %d\n", i);
			}

			// check attempts again
			if (attempts < 1) {
				// TODO: report log
				perror("Exceeded failed attempts.\n");
				exit(EXIT_FAILURE);
			}

			decrypt_steg(argv[2], masterkey);

			free(masterkey);
		}
		else {
			printf("Invalid option\n");
		}
	}

	char *passwd = malloc(100 * sizeof(char));
	printf("Enter password you want to hide: ");
	if (fgets(passwd, sizeof(passwd), stdin) != NULL) {
		char *passwd_id = malloc(100 * sizeof(char));

		printf("Enter password id: ");
		if (fgets(passwd_id, sizeof(passwd_id), stdin)) {
			steg_in_png(argv[1], passwd_id, "1", passwd);
		}
	}

	free(passwd);
	free(passwd_id);
	return 0;
}
