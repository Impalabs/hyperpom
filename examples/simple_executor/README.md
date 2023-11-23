# Simple Executor

This example showcases how an `Executor` object can be used to execute arbitrary AArch64 instructions and then retrieve the CPU and memory states.

## Running the Program

To run the program you can use the `Makefile` provided and simply do:

```
make run
```

If everything went as expected you should see the following input.

```console
$ target/release/hyperpom_example
X0 = 0x42
```
