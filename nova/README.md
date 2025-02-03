## Nexus Nova

Collection of folding schemes implementations using [arkworks](https://arkworks.rs), including:

- Nova[^1]
- SuperNova[^2]
- HyperNova[^3]

The original implementation of Nova, from which we have adopted some utility functions, is due to Microsoft Research – https://github.com/microsoft/Nova. Compared to it, our implementation uses CycleFold[^4], at the cost of bigger verifier's circuit.

## Code structure

```
├── circuits      # implementation of augmented circuits along with IVC (private with re-exports)
├── folding       # folding schemes implementation
├── gadgets       # primitives for the verifier circuits -- mirrors the "folding" module
├── absorb.rs     # cryptographic sponge interface extension
├── commitment.rs # commitment scheme interface
├── provider      # internal traits implementers -- commitment schemes, hashers, etc.
├── ccs           # customizable constraint system primitives
├── r1cs          # R1CS primitives
... snipped
```

## Performance

Benchmarks are available [here](../nova-benches/).

---

[^1]: [Nova: Recursive Zero-Knowledge Arguments from Folding Schemes](https://eprint.iacr.org/2021/370.pdf)
[^2]: [SuperNova: Proving universal machine executions without universal circuits](https://eprint.iacr.org/2022/1758.pdf)
[^3]: [HyperNova: Recursive arguments for customizable constraint systems](https://eprint.iacr.org/2023/573)
[^4]: [CycleFold: Folding-scheme-based recursive arguments over a cycle of elliptic curves](https://eprint.iacr.org/2023/1192)
