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
		while (chr != 0) {
			chr = getc(fptr);

			if (chr == 0) // this loop is for skipping irrelevant parts only -> if 0 or \n, no numth element found
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
		// if getc gets an EOF
		if (chr == 0) {
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

int parse_integer(FILE *fptr, int len_arr, unsigned int num) {
	char *arr = calloc(len_arr, sizeof(char));
	parse_log(fptr, arr, len_arr, num);
	int arr_int = atoi(arr);
	
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
