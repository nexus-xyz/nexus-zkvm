## Nexus Nova benchmarks

Benchmarks code mirrors the reference implementation by Microsoft Research – https://github.com/microsoft/Nova/tree/main/benches.

Benches comparison-results:

| StepCircuit size | Microsoft-Prove | Nexus-Prove | Microsoft-Verify| Nexus-Verify |
| ---------------- | --------------  | ----------- | --------------- | ------------ |
| 0                | 44.201 ms       | 221.17 ms   | 36.907 ms       | 108.81 ms    |
| 6399             | 53.304 ms       | 229.65 ms   | 46.401 ms       | 116.76 ms    |
| 22783            | 74.887 ms       | 244.27 ms   | 69.095 ms       | 143.06 ms    |
| 55551            | 120.05 ms       | 277.11 ms   | 116.09 ms       | 192.72 ms    |
| 121087           | 196.03 ms       | 346.58 ms   | 186.52 ms       | 282.84 ms    |
| 252159           | 335.71 ms       | 498.95 ms   | 319.76 ms       | 476.57 ms    |
| 514303           | 630.94 ms       | 776.78 ms   | 596.13 ms       | 824.23 ms    |
| 1038591          | 1.1913 s        | 1.3661 s    | 1.1284 s        | 1.5852 s     |

Both were executed on the same hardware, commits used:

- Nexus – https://github.com/nexus-xyz/nexus-zkvm/tree/6045c596f2e136aca58e248c993d85a370f983f9
- Microsoft – https://github.com/microsoft/Nova/tree/4f8f3e782b172e98d6d741b29e5bc671ab5b93a6

Results may vary based on your hardware, but the performance ratio should look similar. Microsoft implementation has significantly lower recursion overhead, and as the step circuit size grows, the gap becomes smaller from ~3-4x to 20-30% slowdown.

Hardware used is Ryzen 5900x with 64gb 3600MHz RAM, GPU acceleration **disabled**.

## Running benchmarks

From the `nova-benches` directory

```sh
cargo bench --bench=recursive-snark
```

Flamegraphs are generated with
```sh
cargo bench --bench=recursive-snark -- --profile-time=10
# saves to nova-benches/target/criterion/RecursiveSNARK-StepCircuitSize-*/[Prove/Verify]/profile/flamegraph.svg
```
