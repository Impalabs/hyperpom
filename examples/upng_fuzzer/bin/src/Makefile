NDK_PREBUILTS := $(NDK_PATH)/toolchains/llvm/prebuilt/darwin-x86_64/bin
NDK_CC := $(NDK_PREBUILTS)/aarch64-linux-android31-clang
CC := clang

ifeq ($(TARGET_DIR), )
	TARGET_DIR := .
endif

TARGET := upng
TARGET_PATH := $(TARGET_DIR)/$(TARGET)
TARGET_CFLAGS := -Wall -pedantic -g -O3 -static
TARGET_ASAN := upng.asan
TARGET_ASAN_PATH := $(TARGET_DIR)/$(TARGET_ASAN)
TARGET_ASAN_CFLAGS := -Wall -pedantic -g -O0 -fsanitize=address

.DEFAULT_GOAL := build
.PHONY: check

build:
	$(NDK_CC) -o $(TARGET_PATH) png2tga.c upng.c $(TARGET_CFLAGS)

build-asan:
	$(CC) -o $(TARGET_ASAN_PATH) png2tga.c upng.c $(TARGET_ASAN_CFLAGS)

check: build-asan
	$(TARGET_ASAN_PATH) $(filter-out $@,$(MAKECMDGOALS))

clean:
	rm $(TARGET_PATH)
	rm $(TARGET_ASAN_PATH)
