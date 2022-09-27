# Simple Fuzzer

This example targets the C program found at [`bin/simple_program.c`](bin/simple_program.c).

**Note:** it is not recommended to recompile this program as it might change the symbols' offset and break the fuzzer. If you need to recompile it, you'll need to change the offsets in the `symbols` method in [`src/main.rs`](src/main.rs).

## Running the Program

The `Makefile` provided performs multiple operations detailed below.

 * `build-target`: builds the C program.
 * `clean-target`: cleans the `bin` directory.
 * `build`: builds the fuzzer and the target.
 * `run`: builds the binaries, creates a corpus directory at `./tmp/corpus`, a working directory at `./tmp/work` and then runs the fuzzer.
 * `clean-dirs`: removes the temporary directories `./tmp/corpus` and `./tmp/work`.
 * `clean`: cleans the target, the fuzzer and the temporary directories.

To run the program you can simply do:

```
CERT_KEYCHAIN=${CERT_NAME} make run
```

If everything went as expected, the program should crash after a minute or two:

```
Loading corpus...
Corpus loaded!
[00:00:52] #: 8658541 - Execs/s: 166510 - Paths: 50 - Crashes: 100 (1 uniques) - Timeouts: 0
```

And we should get the following crash:

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
     X0: 0000000000000000    X1: 0000000000101004     X2: 0000000000000000     X3: 0000000000000000
     X4: 0000000000000000    X5: 0000000000000000     X6: 0000000000000000     X7: 0000000000000000
     X8: 00000000cafec0c0    X9: deadbeefdeadbeef    X10: 0000000000101000    X11: 0000000000000000
    X12: 00000000deadbeef   X13: 0000000000000000    X14: 0000000000000000    X15: 0000000000000000
    X16: 0000000000000000   X17: 0000000000000000    X18: 0000000000000000    X19: 0000000000000000
    X20: 0000000000000000   X21: 0000000000000000    X22: 0000000000000000    X23: 0000000000000000
    X24: 0000000000000000   X25: 0000000000000000    X26: 0000000000000000    X27: 0000000000000000
    X28: 0000000000000000   X29: 0000000000000000     LR: 000000000010022c     PC: ffffffffffff0404
     SP: 00000000ffffffd0
EL1:
  SCTLR: 0000000030101185    SP: fffffffffffe1000
   CPSR: 00000000604003c5  SPSR: 00000000600003c0
    FAR: deadbeefdeadbeef   PAR: 0000000000000800
    ESR: 0000000092000044   ELR: 0000000000100254


Backtrace
---------

simple_program 	process+0xd4/0xec	[0x100254]
```

```console
$ ls tmp/work/worker_0*/crashes/* | grep -v info | xargs xxd
00000000: 696d 7061 6c61 6273 696d 7061 6c61 6273  impalabsimpalabs
00000010: 696d 7061 6c61 6273 0000 0000 5b5b       impalabs....[[
```
