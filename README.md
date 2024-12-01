# `z80run` a simple Z80 emulator

`z80run` is a simple Z80 emulator that can run Z80 machine code programs. It is designed to help you debug Z80 programs by providing a simple trace of the instructions and providing inspection and protection of memory regions to catch problems like overindexing or overwriting code.

The hard work of running Z80 instructions and disassembling them is done by `z80.h` and `z80dasm.h` from Andre Weissflog's Chips library.

## Example

```console
unix% ./z80run --load qsort.bin@0xe000 --protect 0xb000-0xffff:rwx | head -10
                R 18 @ Start 
Start           JR QuickSort
                R 3e @ Start+1 
                R ed @ QuickSort 
QuickSort       LD (StackBase),SP
                R 73 @ QuickSort+1 
                R 3e @ QuickSort+2 
                R e0 @ QuickSort+3 
                W ff @ StackBase 
                W df @ StackBase+1 
```

## Compiling

It's a one file program that uses C++20, so just compile it with your favorite C++20 compiler.  For example:

```console
unix% g++ -Wall -std=c++20 -o z80run z80run.cpp
```
