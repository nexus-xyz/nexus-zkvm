# Adding a new Instruction to RISC-V 32IM to Decoder

## Overview

This guide explains how to add a new instruction to RISC-V 32IM without modifying the toolchain.

## Steps

1. Choose an unused encoding
2. Define the instruction format
3. Update the instruction decoder
4. Implement the instruction execution

## Example: Adding f(x) = a * x + b

Let's add a new instruction that computes f(x) = a * x + b, where x is a private input.

### 1. Choose an unused encoding

Use an unused `funct7` value in the existing R-type instruction format:

- `opcode: 0x33 (OPCODE_OP)`
- `funct3: 0b000`
- `funct7: 0b000_0010 (unused value)`

### 2. Define the instruction format

```rust
RType {
    funct7: 0b000_0010,
    funct3: 0b000,
    rd: c,    // destination register
    rs1: a,   // first source register
    rs2: b,   // second source register
}
```

### 3. Update the instruction decoder

Add a new match case in the `process_opcode_op` function:

```rust
match dec_insn.funct3 {
    0b000 => match dec_insn.funct7 {
        0b000_0000 => Some(processor.process_add(dec_insn)),
        0b000_0001 => Some(processor.process_mul(dec_insn)),
        0b010_0000 => Some(processor.process_sub(dec_insn)),
        0b000_0010 => Some(processor.process_fx(dec_insn)), // func3 code for the new instruction
        _ => None,
    },
    // ...
}
```

Implement the `process_fx` function in the `InstructionProcessor` trait:

```rust
impl InstructionProcessor for InstructionDecoder {
    type InstructionResult = Instruction;

    // ...
    impl_r_type_instructions! {
        process_fx => Opcode::CUSTOM0,
    }
}
```

### 4. Implement the instruction execution

Add a new match case in the instruction executor:

```rust
match instruction.opcode {
    // ...
    Opcode::CUSTOM0 => {
        let c = instruction.rd;
        let a = instruction.rs1;
        let b = instruction.rs2;

        let reg_a = registers.get(a);
        let reg_b = registers.get(b);
        let x = get_private_input(); // Function to get the private input

        let result = reg_a * x + reg_b;
        registers.set(c, result);
    }
    // ...
}
```

## Conclusion

By following these steps, you can add a new instructions to RISC-V 32IM without modifying the toolchain, making it easier to extend the instruction set for specific needs.