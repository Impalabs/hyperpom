void func0(void* input_addr);
void func1(void* input_addr);
void func2(void* input_addr);
void func3(void* input_addr);
void func4();

int main(void) {
    void* input_addr = 0x20000;
    func0(input_addr);
}

void func0(void* input_addr) {
    if (*(char *)(input_addr) == 'l') {
        func1(input_addr);
    }
}

void func1(void* input_addr) {
    if (*(char *)(input_addr + 1) == 'y') {
        func2(input_addr);
    }
}

void func2(void* input_addr) {
    if (*(char *)(input_addr + 2) == 't') {
        func3(input_addr);
    }
}

void func3(void* input_addr) {
    if (*(char *)(input_addr + 3) == 'e') {
        func4();
    }
}

void func4() {
    *(unsigned int*)0xdeadbeef = 0xcafec0c0;
}