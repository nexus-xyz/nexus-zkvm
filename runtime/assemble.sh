#!/bin/sh
set -e

# Detect the operating system
if [ "$(uname)" = "Darwin" ]; then
    # macOS
    GCC_PREFIX="riscv64-elf-"
else
    # Assume Linux
    GCC_PREFIX="riscv-none-elf-"
fi

rm -f bin/***.a
for ext in i imc
do
    ${GCC_PREFIX}gcc -c -mabi=ilp32 -march=rv32${ext} -mcmodel=medlow asm.S -o bin/nexus-rt.o
    ${GCC_PREFIX}ar crs bin/riscv32${ext}-unknown-none-elf.a bin/nexus-rt.o
done
rm bin/nexus-rt.o
