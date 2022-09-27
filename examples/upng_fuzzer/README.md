# uPNG Fuzzer

This example targets the [uPNG decoding library](https://github.com/elanthis/upng/).

This project is a good real-world example to showcase Hyperpom's usage considering it has been abandoned for a while now and is already affected by known vulnerabilities that remain [unfixed](https://github.com/elanthis/upng/pull/5).

## Compiling the Target

This step is optional, since the binary is provided, but if you want to recompile it, you'll first need an AArch64 toolchain to compile the binary to an AArch64 ELF.

You can use the [Android NDK](https://developer.android.com/ndk/downloads) for this. Download the NDK and unzip it to a location of your choice (`${NDK_PATH}`).

Then, using the provided `Makefile` you can compile the target program with the following command:

```
NDK_PATH=${NDK_PATH} make build-target
```

## Running the Program

To run the program you can simply do:

```
CERT_KEYCHAIN=${CERT_NAME} make run
```

If everything went as expected, crashes should appear after a few minutes:

```
Loading corpus...
Corpus loaded!
[...]
[00:04:14] #: 16416354 - Execs/s: 64631 - Paths: 208 - Crashes: 134730 (3 uniques) - Timeouts: 0
```

```console
$ cat tmp/work/worker_0*/crashes/*.info

Synchronous Exception from Lower EL using AArch64
=================================================

Crash Reason
------------

EXCEPTION => [syndrome: 000000005a000008, virtual addr: 0000000000000000, physical addr: 0000000000000000]


Virtual CPU State
-----------------

EL0:
     X0: 0000000000000000    X1: 0000000000000004     X2: 0000000000205ddc     X3: 0000000000000006
     X4: 0000000000000000    X5: 0000000000000000     X6: 0000000000000000     X7: 000000000000001d
     X8: 0000000000000026    X9: 0000000000205cdc    X10: 00000000002053dc    X11: ffffffffffffff22
    X12: 000000000000000d   X13: 0000000000000010    X14: 0000000000000003    X15: 0000000000000000
    X16: 0000000000000007   X17: 0000000000000065    X18: 0000000000000000    X19: 0000fffc00000000
    X20: 000000000000001f   X21: 000000000000013c    X22: 0000fffc0000006f    X23: 0000fffc00000052
    X24: 0000000000000065   X25: 0000000000000001    X26: 000000000000ffff    X27: 0000000000000027
    X28: 0000000000205ddc   X29: 0000ffff000fff40     LR: 000000000000001b     PC: ffffffffffff0404
     SP: 0000ffff000fedf0
EL1:
  SCTLR: 0000000030101185    SP: fffffffffffe1000
   CPSR: 00000000204003c5  SPSR: 00000000200003c0
    FAR: 0000fffbffffff91   PAR: 0000000000000800
    ESR: 0000000092000005   ELR: 000000000021ecd8


Backtrace
---------

upng 	upng_decode+0x1a4/0x390	[0x21db88]
upng 	uz_inflate+0xf38/0x10c8	[0x21ecd8]

[...]
```

You can check that these crash are valid using a version of the target built with ASAN.

```console
$ make check /path/to/crashfile
```

You should obtain an output similar to the following:

```
=================================================================
==17672==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x000102e03ce2 at pc 0x000100306ad8 bp 0x00016fb012f0 sp 0x00016fb012e8
READ of size 1 at 0x000102e03ce2 thread T0
    #0 0x100306ad4 in inflate_huffman upng.c:546
    #1 0x1003054d4 in uz_inflate_data upng.c:631
    #2 0x100303e30 in uz_inflate upng.c:670
    #3 0x100303280 in upng_decode upng.c:1078
    #4 0x1002ffcf8 in main png2tga.c:16
    #5 0x10039d088 in start+0x204 (dyld:arm64+0x5088)
    #6 0x25727ffffffffffc  (<unknown module>)

Address 0x000102e03ce2 is a wild pointer inside of access range of size 0x000000000001.
SUMMARY: AddressSanitizer: heap-buffer-overflow upng.c:546 in inflate_huffman
Shadow bytes around the buggy address:
  0x0070205e0740: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0070205e0750: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0070205e0760: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0070205e0770: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0070205e0780: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
=>0x0070205e0790: fa fa fa fa fa fa fa fa fa fa fa fa[fa]fa fa fa
  0x0070205e07a0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0070205e07b0: fa fa fa fa fa fa fa fa 00 00 00 00 00 00 00 00
  0x0070205e07c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0070205e07d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 04
  0x0070205e07e0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==17672==ABORTING
```

**Note:** Corpus majoritarily taken from [go-fuzz-corpus](https://github.com/dvyukov/go-fuzz-corpus/tree/master/png) which is under an [Apache License 2.0](https://github.com/dvyukov/go-fuzz-corpus/blob/master/LICENSE).

## Tracing a Testcase

It is also possible to trace the target with the following command:

```
CERT_KEYCHAIN=${CERT_NAME} make trace /path/to/testcase
```

The resulting trace file can be found in `tmp/trace.txt`.

```console
$ head tmp/trace.txt
0x21efe4: stp x29, x30, [sp, #-0x20]!
0x21efe8: stp x20, x19, [sp, #0x10]
0x21efec: mov x29, sp
0x21eff0: mov x20, x0
0x21eff4: mov w0, #0x50
0x21eff8: mov x19, x1
0x21effc: bl #0x257338
0x257338: paciasp
0x21f000: cbz x0, #0x21f030
0x21f004: adrp x8, #0x206000
```