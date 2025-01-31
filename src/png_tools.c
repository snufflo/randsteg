#include <png.h>
#include <stdio.h>
#include <stdlib.h>

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

	 // if EOF is detected// Allocate memory for row pointers
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
