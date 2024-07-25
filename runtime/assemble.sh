#!/bin/sh

set -e

rm -f bin/*.a

for ext in i imc
do
    riscv64-elf-gcc -c -mabi=ilp32 -march=rv32${ext} -mcmodel=medlow asm.S -o bin/nexus-rt.o
    riscv64-elf-ar crs bin/riscv32${ext}-unknown-none-elf.a bin/nexus-rt.o
done

rm bin/nexus-rt.o
