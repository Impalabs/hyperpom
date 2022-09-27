# Simple Tracer

This example showcases how an `Executor` object can be used to trace an AArch64 program.

## Running the Program

To run the program you can use the `Makefile` provided and simply do:

```
CERT_KEYCHAIN=${CERT_NAME} make run
```

If everything went as expected you should see the following output.

```
0x100000: mov x0, #0
0x100004: mov x1, #0
0x100008: b #0x100024
0x100024: mov x1, #3
0x100028: cmp x0, #0x10
0x10002c: mov x0, #0x20
0x100030: b.eq #0x10001c
0x100034: b #0x10000c
0x10000c: mov x1, #1
0x100010: cmp x0, #0x30
0x100014: b.ne #0x10001c
0x10001c: mov x1, #2
0x100020: b #0x100038
0x100038: ret
```