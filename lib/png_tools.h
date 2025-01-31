#pragma once

#include <png.h>

void write_png(const char *filename, png_bytep *row, int width, int height);

void read_png (const char *filename, png_bytep **row_pointers, int *width, int *height);
