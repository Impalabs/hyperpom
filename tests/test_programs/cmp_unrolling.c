void func0(void* input_addr);
void func1(void* input_addr);
void func2(void* input_addr);
void func3(void* input_addr);
void func4();

int main(void) {
    void* input_addr = 0x20000;
    if (*(unsigned long*)input_addr == 0xdeadbeef44434241)
        *(unsigned int*)0xdeadbeef = 0xcafec0c0;
}
