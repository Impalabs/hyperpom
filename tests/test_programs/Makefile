CC := gcc
OBJCOPY := objcopy

CFLAGS := -fPIC -fpie -ffreestanding -ffunction-sections  -fomit-frame-pointer \
		  -fno-exceptions -fno-unwind-tables

define build_test
	$(CC) $(CFLAGS) -I. -o $1 $1.c
	$(OBJCOPY) -O binary --strip-all $1
endef

.PHONY: simple_test cmp_unrolling

simple_test:
	$(call build_test, simple_test)

cmp_unrolling:
	$(call build_test, cmp_unrolling)
