#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../lib/log_tools.h"

#define MAX_ID_LEN 50

int parse_log(FILE *fptr, char *arr, int len_arr, unsigned int num) {
	long original_fptr_pos = ftell(fptr); // Save original position
	char *tmp_id = calloc(len_arr, sizeof(char));
	int chr;
	int len_str = 0;
	int status = 0;
	int count = 0;

	if (num > 5) {
		perror("parse_log(): num is too big");
		exit(EXIT_FAILURE);
	}

	// TODO: might need to fix this
	// skip irrelevant columns
	for (int i=0;i<num;i++) {
		while (chr != EOF) {
			chr = getc(fptr);

			if (chr == EOF) // this loop is for skipping irrelevant parts only -> if 0 or \n, no numth element found
				return 2;
			else if ((char) chr == '\n') 
				return 2;
			else if ((char) chr == '$')
				break;
		}
	}
	chr = 0;

	// get chr until first delimiter or end of string and save value into tmp_id
	len_str = 0;
	for (;len_str < len_arr;len_str++) {
		chr = getc(fptr);

		if (chr == EOF) {
			// register EOF condition
			status = 1;
			break;
		}
		else if ((char) chr == '$' || (char) chr == '\n')
			break;

		tmp_id[len_str] = (char) chr;
	}

	fseek(fptr, original_fptr_pos, SEEK_SET); // Restore position

	if (len_str > len_arr) {
		perror("LOG: allocated space is too small");
		free(tmp_id);
		tmp_id = NULL;
		return 2;
	}

	memcpy(arr, tmp_id, len_str);
	free(tmp_id);
	tmp_id = NULL;
	return status;
}

int parse_integer(FILE *fptr, int max_len_arr, unsigned int num) {
	char *arr = calloc(max_len_arr, sizeof(char));
	int status = parse_log(fptr, arr, max_len_arr, num);
	if (status == 2) {
		perror("EOF");
		return -1;
	}
	int arr_int;
	
	if ((arr_int = atoi(arr)) == 0) {
		perror("LOG: read fail");
		return 1;
	}
	free(arr);
	arr = NULL;

	return arr_int;
}

void write_delimiter(FILE *fptr) {
	if (fwrite("$", sizeof(char), 1, fptr) != 1) {
		perror("Error writing delimiter to log.txt");
		exit(EXIT_FAILURE);
	}
}

void delete_line(char *id) { // TODO: implement further
	char *log_id[MAX_ID_LEN] = {0};
	char *buf;
	char chr = 0;
	int int_chr = 0;
	int multiplier = 0;
	int buf_len = 0;
	int status = 0;
	int parse_status = 0;

	FILE *fptr = fopen("log.txt", "r");
	if (fptr == NULL) {
		perror("Failed to open log file");
		return;
	}

	FILE *tmp_fptr = fopen("tmp.txt", "w");
	if (tmp_fptr == NULL) {
		perror("Failed to open tmp file");
		return;
	}
	
	while (1) { // better way to loop?
		parse_status = parse_log(fptr, log_id, MAX_ID_LEN, 0);
		if (parse_status == 2) {
			perror("length of array is too small for log value");
		}

		// dynamically allocate space for string and save it to buf
		multiplier = parse_integer(fptr, 10, 1);
		if (multiplier > 0) { // check if EOF has been hit
			buf_len = MAX_ID_LEN + 10 * 2 + multiplier * 16 * 2 + 16 * 2; // passwd_id $ multiplier $ max_digits $ hex_coordinates $ iv $ iv
			buf = malloc(buf_len); 
		}
		if (!fgets(buf, buf_len, fptr)) // fgets returns NULL if EOF has been reached
			break;

		if (strcmp(log_id, id) == 0) { // target id detected
			memset(buf, 0, buf_len);
			status = 1;
		}
		else// copy string to tmp_fptr
			fputs(buf, tmp_fptr);

		memset(log_id, 0, MAX_ID_LEN);
		chr = 0;
		int_chr = 0;
		free(buf);
		buf = NULL;
	} 

	if (status != 1)
		perror("id not found");

	fclose(fptr);
	fclose(tmp_fptr);

	remove("log.txt");
	rename("tmp.txt", "log.txt");
}

void fprint_to_hex(FILE *fptr, unsigned char *buf, int buf_len) {
	for (int i=0;i<buf_len;i++) {
		fprintf(fptr, "%02x", buf[i]);
	}
}

void bytes_to_hex(unsigned char *buf, int buf_len, unsigned char *hex) {
	for (int i=0;i<buf_len;i++) {
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

void list_passwd_id(FILE *fptr) {
	char id[MAX_ID_LEN] = {0};
	int c;
	int status = 0;
	int parse_status = 0;
	
	printf("List of all password IDs:\n");
	while (status != 1) {
		parse_status = parse_log(fptr, id, MAX_ID_LEN, 0);
		if (parse_status == 2) {
			perror("no ids found");
			exit(EXIT_FAILURE);
		}

		while ((c = getc(fptr)) != '\n') { // go to new line
			if (c == EOF) {
				status = 1;
				break;
			}
		}

		printf("%s\n", id);
		memset(id, 0, MAX_ID_LEN);
	}
	
}
