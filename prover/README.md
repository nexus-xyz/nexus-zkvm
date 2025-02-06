# Nexus zkVM Prover

This serves as the foundation of the zkVM, tasked with capturing and synthesizing the execution trace into a succinct, zero-knowledge proof.

## Known Limitations

* The protocol doesn't support read-only or write-only memory regions.
* The protocol doesn't know that the program is on the RAM. Load instructions on the program will result in loading zero value (or any initial value in the public input).