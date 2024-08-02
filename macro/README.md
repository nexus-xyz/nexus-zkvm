# Helper macros for Host development 

This crate provides a few helper macros for Host development.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
nexus-macro = { path = "../macro" }
nexus-profiler = { path = "../macro/profiler" }
```

## Profile macros

### Requirements

Install `go` programming language.

#### MacOS

```bash
brew install go
```

#### Linux

```bash
sudo apt install golang-go
```

### How to use `#[profile]` macro

At any host function, you can use `#[profile]` to profile the function.

```rust
use nexus_macro::profile;

#[profile]
pub fn eval_inst(vm: &mut NexusVM<impl Memory>) -> Result<()> {
    /// .....
    /// .....
}

#[profile("is_satisfied.pb")]
pub fn is_satisfied<C: CommitmentScheme<G>>(
        &self,
        U: &R1CSInstance<G, C>,
        W: &R1CSWitness<G>,
        pp: &C::PP,
    ) -> Result<(), Error> {
        /// ...
        /// ....
    }

```

When the profile output name is undefined, the function name is used as default with suffix `.pb`.
The first macro will write the profile data to `eval_inst.pb`. The second macro will write the profile data to `is_satisfied.pb`.

You can open the `.pb` file with `go tool pprof -http=127.0.0.1:8000 [function_name].pb`


