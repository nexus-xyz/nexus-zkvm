#![no_std]
#![no_main]

#[nexus_rt::main]
fn main() {
    fn f(n: u32) -> u32 {
        if n <= 1 {
            1
        } else {
            // n * f(n - 1) would panic if the factorial overflows u32::MAX in debug build,
            // and wrap around in release. Therefore, use built-in checked methods to make
            // the output deterministic.
            n.saturating_mul(f(n - 1))
        }
    }
    let n = core::hint::black_box(12);
    let _result = f(n);
}
