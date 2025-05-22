# Precompile Implementation Details

The precompile lifecycle looks roughly like this:

1. Writing the precompile. Regardless of the precompile's nature, it has to be written, tested, and audited on its own before ever being included in a guest program or run on the VM.
2. Publishing the precompile. After the precompile has been suitably tested and audited, it has to be made available to users. Currently, we plan on using standard [Rust crates](https://crates.io/) for handling publication and versioning. Auditing and testing will likely rely on manual review for the time being.
3. Writing a guest program that uses the precompile. Because the guest program is built and linked before being proven, this step can rely on compilation and macros without any loss in portability.
4. Running the guest program that uses the precompile. The VM has to be able to interpret the precompile's custom instruction and execute its custom functionality without requiring any re-compilation of the VM or precompile.
5. Proving the guest program's execution. This relies on being able to fetch, interpret, and prove the precompile's circuits.

This document contains implementation notes and details for each of these steps.

## Concepts/Terminology

**Dynamic Precompile**: the "usual" type of precompile. Relies on the implementation being shipped alongside the VM as dynamically executable third-party code. These can be either first or third party.

**Static Precompile**: the "custom" type of precompile that has to be compiled into the VM itself. These precompiles are *always* present in the VM and are always interpretable by the emulator. Examples include `rin` and `wou`. These feature almost the same interface as dynamic precompiles, but they have separate handling for the VM's first and second passes, and in both cases they're allowed to interact with a mutable reference to the VM itself. Static precompiles are always first party.

## RISC-V Instruction Encoding

We've chosen to use custom instructions for our precompiles (instead of syscalls via `ECALL`). [Chapter 34 of the RISC-V spec](https://github.com/riscv/riscv-isa-manual/releases/download/20240411/unpriv-isa-asciidoc.pdf) mandates that certain opcodes are reserved for custom use &mdash; these opcodes will *never* be used for any official RISC-V extension. We'll use these opcodes for our precompiles.

Specifically, we have the following available to us:

| Opcode (`inst[6:0]`) | RISC-V Designation | Our Use |
| --- | --- | --- |
| `0001011` | `custom-0` | R-type precompiles |
| `0101011` | `custom-1` | I-type precompiles |
| `1011011` | `custom-2/rv128` | S-type precompiles |
| `1111011` | `custom-3/rv128` | Unused |

The `rv128` tag means that these instructions might be used in the RISC-V 128-bit instruction set but are still reserved for custom use in RV32 and RV64, which should more than cover our roadmap.

And this is how we'll break down the instruction's components:

| Our Use | `opcode` (`inst[6:0]`) | `rd` | `rs1` | `rs2` |`imm` | `fn` |
| --- | --- | --- | --- | --- | --- | --- |
| R-type precompiles |`0001011` | `inst[11:7]` | `inst[19:15]` | `inst[24:20]` | N/A | `fn3 = inst[14:12]` and `fn7 = inst[31:25]` |
| I-type precompiles |`0101011` | `inst[11:7]` | `inst[19:15]` | N/A | `imm[11:0] = inst[31:20]` | `fn3 = inst[14:12]` |
| S-type precompiles |`1011011` | N/A | `inst[19:15]` | `inst[24:20]` | `imm[11:5] = inst[31:25]` and `imm[4:0] = inst[11:7]` | `fn3 = inst[14:12]` |

These intentionally follow the existing format for R-, I-, and S-type RV32 instructions. Counting, we can see that a given program has space for $2^{10}$ R-type precompiles and $2^3$ for each of I- and S-type precompiles.

For the sake of simplicity, I- and S-type precompiles will be reserved for static precompiles (i.e., `rin` and `wou`). Unless incredibly compelling use-cases emerge, leaving registers unused in an R-type instruction + forcing users to use `addi` and `lui` seems like a perfectly serviceable workflow.

If being limited to $2^{10}$ dynamic precompiles in a guest program ever becomes a practical limit, we can use the unused `custom-3` opcode to double that number, and we can start to create truly custom instruction formats should $2^{11}$ still prove not enough. The rest of this design will ignore cases where 1,024 dynamic precompiles is insufficient.

This makes the emulator instruction interpretation quite simple: we have 3 new opcodes to scan for, each of which uses existing code to extract the registers and function codes from the instruction. The static precompiles can be implemented directly as new instructions, whereas dynamic precompiles all have uniform but generalized handling as a unique third instruction.

## Dynamic Name Mapping

We don't want to statically assign instructions to precompiles as that would limit our zkvm to a small, finite number of precompiles in the entire ecosystem. In order to keep our ELF files self-contained, we want to describe how to map instructions (the `fn3` and `fn7` values, in our case) onto actual implementations of precompiles in the ELF file itself.

We can use [`#link_section`](https://doc.rust-lang.org/reference/abi.html#the-link_section-attribute) and [`#no_mangle`](https://doc.rust-lang.org/reference/abi.html#the-no_mangle-attribute) to embed a static string under a particular symbol in a particular section of the guest binary. When the VM loads the binary, it can parse these strings and use them to link custom instructions to the correct precompile implementation.

We can emit this information by using macros to embed code that expands to the following:

```rust
#[no_mangle]
#[link_section=.note.nexus-precompiles]
pub static DYNAMIC_PRECOMPILE_{idx}: &str = "{content}";
```

Where `idx = fn7||fn3` is a 10-bit number expressed in binary. `content` is generated by using the relevant library function on a `DynamicPrecompileDescriptor` struct. The code in the `/precompiles/` crate is authoritative.

## Writing Static Precompiles

Since static precompiles are integral to the VM, they should be implemented like any other instruction, with no special treatment except ensuring the instruction encoding follows this guide.

### Short Term/MVP

Since we require that dynamic precompiles be built and run alongside the VM, they can directly register themselves using a `register_precompile` interface that thinly wraps `add_opcode`, integrating the dynamic precompiles directly into the VM. This should be a minimal-effort solution that works to provide robust precompile functionality to the VM.

### Longer Term

In the longer term, we want to support the use of using precompiles in a network proving context. This can be achieved by slightly generalizing the role of the precompile: instead of dynamic precompiles being processed as instructions, they can all be interpreted and dispatched by a uniform handler, which becomes a static precompile I'll call `dynprec` for convenience (it's a bad name though). `dynprec`'s implementation should be as minimal as possible given that dynamic precompiles aren't allowed any VM-specific functionality, but it provides a good way to abstract future concerns around sandboxing, library loading logistics, etc. from the core VM logic.

## Writing Dynamic Precompiles

Dynamic precompiles need to be implemented independent of the VM or guest programs but need to be API-compatible with both, so the precompile interfaces are defined here, in `/precompiles/`, instead of in either `/runtime/` or `/vm/`.

While dynamic precompiles can be included as source dependencies by guest programs, they have to be executed dynamically by the VM. ~~This means that code involved in calling precompile functionality from guest programs can use macros and Rust-native functionality while the precompile implementation called by the VM has to follow the portable `extern "C"` FFI~~. Because we're not targeting networked precompile distribution at the moment, we're allowing precompiles to be rebuilt locally, as needed, using the same unstable Rust ABI as the locally built VM.

This means that the contract implementers have to follow can be a clean, Rusty interface based on the `InstructionState` and `InstructionExecutor` traits. At runtime, these instructions can be loaded into the `InstructionExecutorRegistry` via its dynamic precompile table.

The relevant types and interfaces will be specified in the `nexus-common` crate (moved from their current definition in the VM crate).

## Packaging Precompile Implementations

*Note: this section doesn't apply to the current MVP implementation effort since we're not targeting networked provers being able to use precompiles. Instead, precompile users will just compile them locally.*

Precompile implementations must be executable by provers without requiring local compilation. The precompile implementation should be packaged as a shared library (.so, .dylib, or .dll, depending on the platform) with a single exported symbol nexus_zkvm_precompile_eval, following the relevant function specification in the /precompiles/ crate. Precompile implementations are shipped as binaries paired with manifests that describe their authorship and provenance.

The precompile example project(s) should automatically target the appropriate shared library output and include macros for annotating that a given function should be the entrypoint for that precompile's implementation. The `/precompiles/` crate also contains utility tools for generating distributable precompile manifests and loading those for use by the VM.

The proving circuit also needs to be encoded as a part of the precompile manifest and loaded by the prover after trace generation. Implementation here is pending implementation of basic operation proving, as that will inform how this is done. For now, we include an empty dummy blob whose place will later be taken by an appropriate representation of the precompile's proof circuit.

In the future, we should strongly consider an approach to sandboxing these distributed binary files. The Rust-native approach seems to prefer using wasm, but there are other robust approaches to sandboxing that exist in the wild too. As a part of publishing, we should describe our integrity checking mechanisms for precompiles.

## Publishing Precompiles

We know we want to use [crates.io](https://crates.io), but finalizing publication processes isn't part of the MVP for precompiles. This section is `TODO`.
