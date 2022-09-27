#define MAGIC_VALUE 0xdeadbeef
#define INIT_STATE 0x0bad0d0e

/* Global state variable. */
int g_state = 0;
char g_magic_string[0x11];

void init(int magic);
int sum(char* buffer, unsigned int size);
int process(char* buffer, unsigned int size);
unsigned int strlen(const char *str);
int strcmp(const char *s1, const char *s2);
unsigned long hex2long(const char *str);

/* The main function. */
int main(int argc, char *argv[]) {
    if (argc < 3)
        return -1;

    /*
     * Converts the first argument into a number from an hexadecimal
     * representation.
     */
    unsigned int magic = hex2long(argv[1]);
    init(magic);

    /* Retrieves information about the buffer and calls the process function. */
    char* buffer = argv[2];
    unsigned int size = strlen(buffer);
    return process(buffer, size);
}

/* Sets the global state variable to the initial state value. */
void init(int magic) {
    /*
     * The argument should be equal to the expected magic value.
     * This is mostly an excuse to show how a function can be called from the
     * fuzzer using arbitrary arguments.
     */
    g_state = (magic == MAGIC_VALUE) ? INIT_STATE : 0;

    /*
     * The global magic string is initialized in this function so we don't need
     * to care about loading the string from the binary's data section.
     */
    *(unsigned long*)g_magic_string = 0x7362616c61706d69;
    *(unsigned long*)(g_magic_string + 8) = 0x7362616c61706d69;
    g_magic_string[0x10] = 0;
}

/* Computes the sum of the bytes in `buffer`. */
int sum(char* buffer, unsigned int size) {
    int sum = 0;
    for (int i = 0; i < size; i++) {
        sum += buffer[i];
    }
    return sum;
}

/* Processes the user input */
int process(char* buffer, unsigned int size) {
    /* Returns if we're not currently in the initialization state */
    if (g_state != INIT_STATE)
        return -2;

    /* Checks that the input is big enough. */
    if (size <= 24)
        return -3;

    /*
     * Pre-check verifying that the sum of the input is the expected one
     * before proceeding further. These types of functions can be arbitrarily
     * hard to pass while fuzzing, so it's better to just place a hook that
     * returns the correct value and ignore them.
     */
    if (sum(buffer, size) != 0x9db)
        return -4;

    /* Verifies that the buffer starts with the expected input. */
    if (*(unsigned long*)buffer != 0x7362616c61706d69)
        return -5;

    /* Verifies that the buffer contains the rest of the string. */
    if (strcmp(buffer + 8, g_magic_string))
        return -6;

    /* If we managed to reach this point, crash the program. */
    *(unsigned long*)0xdeadbeefdeadbeef = 0xcafec0c0;

    return 0;
}

/* strlen implementation */
unsigned int strlen(const char *str) {
    const char *s = str;
    while (*s++);
    return (s - str);
}

/* strcmp implementation */
int strcmp(const char *s1, const char *s2) {
    unsigned char c1, c2;
    do {
        c1 = *s1++;
        c2 = *s2++;
        if (c1 == 0)
            return c1 - c2;
    } while (c1 == c2);
    return c1 - c2;
}

/*
 * Converts a string that contains an hexadecimal representation of a number
 * into a 64-bit integer.
 * Equivalent to strtol(str, 0, 16).
 */
unsigned long hex2long(const char *str) {
    unsigned long res = 0;
    char c;
    while ((c = *str++)) {
        char v = (c & 0xF) + (c >> 6) | ((c >> 3) & 0x8);
        res = (res << 4) | (unsigned long) v;
    }
    return res;
}