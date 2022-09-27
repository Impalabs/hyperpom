CC := clang
OBJCOPY := objcopy
RM := rm

CFLAGS := -fPIC -fpie -ffreestanding -ffunction-sections  -fomit-frame-pointer \
		  -fno-exceptions -fno-unwind-tables -O0
TARGET := simple_program
TARGET_SRC := $(TARGET).c

.DEFAULT_GOAL := build

build-macho:
	$(CC) $(CFLAGS) -o $(TARGET) $(TARGET_SRC)

build: build-macho
	$(OBJCOPY) -O binary $(TARGET)

clean:
	$(RM) $(TARGET)