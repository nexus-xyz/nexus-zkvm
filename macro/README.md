# Helper macros for development 

This crate provides a few helper macros for development.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
nexus-macro = { path = "../macro" }
nexus-profiler = { path = "../macro/profiler" }
```

## Profile macros

At any function, you can use `#[profile]` to profile the function.

```rust
use nexus_macro::profile;

#[profile]
fn compute_numbers() {
    let mut sum = 0;
    for i in 0..=1000 {
        sum += i;
    }
    println!("Sum of numbers from 0 to 1000: {}", sum);
}

#[profile("compute_numbers_with_name.pb")]
fn compute_numbers_with_name() {
    let mut sum = 0;
    for i in 0..=1000 {
        sum += i;
    }
    println!("Sum of numbers from 0 to 1000: {}", sum);
}

```

When the profile output name is undefined, the function name is used as default with suffix `.pb`.
The first macro will write the profile data to `compute_numbers.pb`. The second macro will write the profile data to `compute_numbers_with_name.pb`.

You can open the `.pb` file with `go tool pprof -http=127.0.0.1:8000 [function_name].pb`


