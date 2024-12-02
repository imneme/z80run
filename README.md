# `z80run` - A Z80 Program Debugger and Memory Tracer

`z80run` is a debugging tool for Z80 machine code that provides instruction tracing, memory protection, and variable watching. It helps catch common issues like buffer overruns, stack overflows, and memory corruption by allowing you to monitor memory access and protect specific memory regions.

The Z80 emulation and instruction disassembly are handled by Andre Weissflog's excellent Chips library (`z80.h` and `z80dasm.h`).

## Features

- Instruction-by-instruction tracing with cycle counts
- Memory access monitoring (reads, writes, and instruction fetches)
- Memory protection (specify allowed read/write/execute permissions for memory ranges), allowing you to catch buffer overflows, stack overflows, and other memory corruption issues
- Variable watching (monitor changes to bytes, words, or ranges of memory)
- Symbol table support (automatically loads `.sym` files for `.bin` files)
- Case-insensitive symbol lookup with offset support (e.g., `symbol+2`)

## Example Usage

Here's an example showing various features in action:

```console
./z80run --load program.bin@0xe000 --stack STACK \
         --watch-word lowIdx --watch-word highIdx \
         --watch-range buffer-buffer+16 \
         --protect 0x0-stack-101 --protect stack-100-stack:rw \
         --protect QuickSort-0xffff:x --max-cycles 120
```

This command:

- Loads `program.bin` at address 0xE000
- Sets the stack pointer to the value of the symbol `STACK`
- Watches two 16-bit variables, `lowIdx` and `highIdx`
- Watches 16 bytes starting at 'buffer'
- Protects memory from 0 to STACK-101 from all access
- Protects the stack region from STACK-100 to STACK, only allowing reads and writes (code execution is disallowed)
    - Note: `stack-100-stack:rw` may seem like it's abiguous, but `100-stack` is not a valid end point for the region so the `100` must belong to the start point. But if it troubles you you can always use `stack-100-stack-0:rw` or `'stack-100 - stack:rw'` instead.
- Protects the memory range from QuickSort to 0xFFFF from data access, only allowing code execution
- Runs for at most 120 cycles

The output shows instruction execution, memory access, and detected changes:

```console
      1: Start                  JR QuickSort
     13: QuickSort              LD (StackBase),SP
     27:                                W fd @ StackBase
     30:                                W df @ StackBase+1
     33: QuickSort+4            LD HL,0000h
     43: QuickSort+7            LD (lowIdx),HL
     53:                                W 00 @ lowIdx
     56:                                W 00 @ lowIdx+1
     59:                                        Watch lowIdx: 0000
     59: QuickSort+10           LD HL,(N)
     69:                                R 0a @ N
     72:                                R 00 @ N+1
     75: QuickSort+13           DEC HL
     81: QuickSort+14           LD (highIdx),HL
     91:                                W 09 @ highIdx
     94:                                W 00 @ highIdx+1
     97:                                        Watch highIdx: 0000 -> 0009
     97: QuickSort+17           CALL PushLowHigh
    108:                                W e0 @ STACK-3
    111:                                W 54 @ STACK-4
    114: PushLowHigh            POP AF
    118:                                R 54 @ STACK-4
    120: Reached maximum cycle count (120)
```

## Command Line Options

- `--load file@addr` - Load binary file at specified address/symbol
- `--start addr` - Set program counter start address
- `--stack addr` - Set initial stack pointer
- `--max-cycles N` - Run for at most N cycles
- `--protect range:flags` - Protect memory range (flags: r=read, w=write, x=execute)
- `--logopts options` - Set logging options. Combine the options below. Use captial letters to disable rather than enable.
    - `c` - Show instruction cycles
    - `i` - Print (disassemble) instructions as they're executed
    - `r` - Show memory reads
    - `w` - Show memory writes
    - `f` - Show instruction fetches
    - `v` - Show memory protection violations
    - `a` - Show all (equivalent to `cirwfv`); if you want to begin with a blank slate, use `A` as the first option
    - `m` - Show most (equivalent to `aF`), the default (everything except instruction fetches)

Memory watching:
- `--watch addr` - Watch byte at address
- `--watch-word addr` - Watch 16-bit word
- `--watch-long addr` - Watch 32-bit value
- `--watch-range start-end` - Watch range of memory.

All addresses can be specified as hex values or symbols (with optional +/- offsets).

## Symbol Files

When loading a `.bin` file, `z80run` automatically looks for a corresponding `.sym` file (e.g., `program.sym` for `program.bin`). Symbol files should contain EQU directives in the format:

```
SYMBOL  EQU  1234H
```

## Building

### Get the Dependencies

Run `./download-deps.sh` to download the required header files from Andre Weissflog's Chips library.  These are header-only libraries, so no special installation is required.

Or manually download:
- `z80.h` from https://github.com/floooh/chips/blob/master/chips/z80.h
- `z80dasm.h` from https://github.com/floooh/chips/blob/master/util/z80dasm.h

### Build

Requires a C++20 compiler:

```console
g++ -Wall -std=c++20 -o z80run z80run.cpp
```
