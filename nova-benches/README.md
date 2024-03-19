## Nexus Nova benchmarks

Benchmarks code mirrors the reference implementation by Microsoft Research – https://github.com/microsoft/Nova/tree/main/benches.

Sample results are available at [bench-results](./bench-results/). Benches were executed on the same hardware, commits used: 

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
```
cargo bench --bench=recursive-snark -- --profile-time=10
# saves to nova-benches/target/criterion/RecursiveSNARK-StepCircuitSize-*/[Prove/Verify]/profile/flamegraph.svg
```
