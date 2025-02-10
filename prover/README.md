# Nexus zkVM Prover

RISC-V virtual machine prover built with https://github.com/starkware-libs/stwo.

Columns used in the AIR trace are specified in [src/column.rs](src/column.rs), constraints for each component can be found in [src/chips](src/chips).

## Benchmarks

Synthetic benchmarks are available in [prover-benches](../prover-benches/).

## Known Limitations

* The protocol doesn't support read-only or write-only memory regions.
* The protocol doesn't know that the program is on the RAM. Load instructions on the program will result in loading zero value (or any initial value in the public input).
