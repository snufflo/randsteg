#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ID_LEN 50

/**
 * @brief saves the [num]th element to [arr] from the line, where [fptr] is at
 *
 * @param fptr the log file that is to be parsed
 * @param arr array where parsed value is to be saved
 * @param len_arr length of arr
 * @param num column number of desired value
 * @return 1 if EOF has been detected
 * @raturn 2 if len_arr is smaller than the value to be saved
 */
int parse_log(FILE *fptr, char *arr, int len_arr, unsigned int num);

// @brief converts [num]th element in [fptr] from current line into integer and returns it. [max_len_arr] is the max amount of digits, the number can have
int parse_integer(FILE *fptr, int max_len_arr, unsigned int num);

// @brief writes '$' into fptr
void write_delimiter(FILE *fptr);

void delete_line(char *id);

// @brief writes [buf_le] characters from [buf] into [fptr] hex encoded
void fprint_to_hex(FILE *fptr, unsigned char *buf, int buf_len);

// @brief converts [buf_len] bytes from [buf] into [hex] in hex encoding
void bytes_to_hex(unsigned char *buf, int buf_len, unsigned char *hex);

// @brief converts [hex_len] bytes from [hex] into [output] in hex decoding
int hex_to_bytes(const char *hex, int hex_len, unsigned char *output);

// @brief lists all password ids in log.txt
void list_passwd_id(FILE *fptr);
