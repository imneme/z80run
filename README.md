# `z80run` - A Z80 Program Debugger and Memory Tracer

`z80run` is a debugging tool for Z80 machine code that provides instruction tracing, memory protection, and variable watching. It helps catch common issues like buffer overruns, stack overflows, and memory corruption by allowing you to monitor memory access and protect specific memory regions.

The Z80 emulation and instruction disassembly are handled by Andre Weissflog's excellent Chips library (`z80.h` and `z80dasm.h`).

## Features

- Instruction-by-instruction tracing with cycle counts
- Memory access monitoring (reads, writes, and instruction fetches)
- Memory protection (specify allowed read/write/execute permissions for memory ranges)
- Variable watching (monitor changes to bytes, words, or ranges of memory)
- Symbol table support (automatically loads `.sym` files for `.bin` files)
- Case-insensitive symbol lookup with offset support (e.g., `symbol+2`)

## Example Usage

Here's an example showing various features in action:

```console
./z80run --load program.bin@0xe000 --stack stack-2 \
         --watch-word counter --watch-range buffer-buffer+16 \
         --protect 0-stack:rwx --max-cycles 1000
```

This command:
- Loads `program.bin` at address 0xE000
- Sets the stack pointer to STACK-2
- Watches a word-sized variable named 'counter'
- Watches 16 bytes starting at 'buffer'
- Protects memory from 0 to STACK with read/write/execute permissions
- Runs for at most 1000 cycles

The output shows instruction execution, memory access, and detected changes:

```console
      1: Start                  JR QuickSort
     13: QuickSort              LD (StackBase),SP
     27:                                W fd @ StackBase
     30:                                W df @ StackBase+1
     33: QuickSort+4            LD HL,0000h
                                        Watch counter: 0000 -> 1234
```

## Command Line Options

- `--load file@addr` - Load binary file at specified address/symbol
- `--start addr` - Set program counter start address
- `--stack addr` - Set initial stack pointer
- `--max-cycles N` - Run for at most N cycles
- `--protect range:flags` - Protect memory range (flags: r=read, w=write, x=execute)

Memory watching:
- `--watch addr` - Watch byte at address
- `--watch-word addr` - Watch 16-bit word
- `--watch-long addr` - Watch 32-bit value
- `--watch-range start-end` - Watch range of memory

All addresses can be specified as hex values or symbols (with optional +/- offsets).

## Symbol Files

When loading a `.bin` file, `z80run` automatically looks for a corresponding `.sym` file (e.g., `program.sym` for `program.bin`). Symbol files should contain EQU directives in the format:

```
SYMBOL  EQU  1234H
```

## Building

### Get the Dependencies

Run `./download-deps.sh` to download the required header files from Andre Weissflog's Chips library.  These are header-only libaries, so no special installation is required.

Or manually download:
- `z80.h` from https://github.com/floooh/chips/blob/master/chips/z80.h
- `z80dasm.h` from https://github.com/floooh/chips/blob/master/util/z80dasm.h

### Build

Requires a C++20 compiler:

```console
g++ -Wall -std=c++20 -o z80run z80run.cpp
```

