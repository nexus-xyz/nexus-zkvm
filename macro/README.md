# Helper macros for Host development 

This crate provides a few helper macros for Host development.

## Requirements

Install `go` programming language.

#### MacOS

```bash
brew install go
```

#### Linux

```bash
sudo apt install golang-go
```


## Usage

### How to use `#[profile]` macro in SDK

For SDK user, this macro is already provided in `Cargo.toml` in `nexus-sdk` crate.


The `nexus_macro` is re-exported in `nexus-sdk`.

To use `#[profile]` macro in SDK, one must import the profiler dependency: 

```toml
[dependencies]
nexus-profiler = { git = "https://github.com/nexus-xyz/nexus-zkvm/macro/profiler" }
```

```rust
use nexus_sdk::nexus_macro::profile;

#[profile]
fn compile_program(opts: CompileOpts) {
    Nova::compile(&opts).expect("failed to compile guest program")
}
```

In SDK, you must include the `use sdk::nexus_macro::profile;` to use the `#[profile]` macro.
The code above will generate 1 file `compile_program.pb` in the current directory.

You can open the `.pb` file with `go tool pprof -http=127.0.0.1:8000 compile_program.pb`


### How to use `#[profile]` macro in development

For Nexus developer, if you want to use this macro in your crate.
Add this to your crate `Cargo.toml`:

```toml
[dependencies]
nexus-macro = { path = "../macro/" }
nexus-profiler = { path = "../macro/profiler" }
```

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

Build with `cargo build --release` to build in release mode.

You can open the `.pb` file with `go tool pprof -http=127.0.0.1:8000 [function_name].pb`


### Warning

*Note:* This macro is supposed to be used for one-time-call function. It won't accumulate data if you call the function multiple times.

The wrong way to use this macro.

```rust
#[profile]
pub fn eval_inst(vm: &mut NexusVM<impl Memory>) -> Result<()> {
    /// ... 
}

pub fn eval_inst_top(vm: &mut NexusVM<impl Memory>) -> Result<()> {
    for _ in 0..100 {
        eval_inst(vm)?;
    }
}
```
The first example will only profile the last call of `eval_inst` and omit 99 calls.


The right way to use this macro.

```rust
pub fn eval_inst(vm: &mut NexusVM<impl Memory>) -> Result<()> {
    /// ... 
}

#[profile]
pub fn eval_inst_top(vm: &mut NexusVM<impl Memory>) -> Result<()> {
    for _ in 0..100 {
        eval_inst(vm)?;
    }
}
```

The second example will profile the whole `eval_inst_top` function.