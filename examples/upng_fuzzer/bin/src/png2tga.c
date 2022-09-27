#include <stdio.h>

#include "upng.h"

#define HI(w) (((w) >> 8) & 0xFF)
#define LO(w) ((w) & 0xFF)

int main(int argc, char** argv) {
	upng_t* upng;

	if (argc <= 1) {
		return 0;
	}

	upng = upng_new_from_file(argv[1]);
	upng_decode(upng);
	upng_free(upng);
	return 0;
}

