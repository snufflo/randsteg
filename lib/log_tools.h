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

int parse_integer(FILE *fptr, int len_arr, unsigned int num);

void write_delimiter(FILE *fptr);
