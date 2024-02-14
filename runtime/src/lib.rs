#![no_std]
#![doc = include_str!("../README.md")]

// Nexus VM runtime environment
// Note: adapted from riscv-rt, which was adapted from cortex-m.

use core::alloc::{GlobalAlloc, Layout};
use core::panic::PanicInfo;

pub use nexus_rt_macros::main;

mod ecalls;
pub use ecalls::*;

#[inline(never)]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    extern "C" {
        fn abort() -> !;
    }
    write_log("PANIC\n");
    unsafe {
        abort();
    }
}

#[export_name = "error: nexus-rt appears more than once"]
#[doc(hidden)]
pub static __ONCE__: () = ();

struct Heap;

#[global_allocator]
static HEAP: Heap = Heap;

// This trivial allocate will always expand the heap, and never
// deallocates. This should be fine for small programs.

unsafe impl GlobalAlloc for Heap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        extern "C" {
            fn alloc_(size: usize) -> *mut u8;
        }

        let sz = layout.size();
        let sz = (sz + 3) & !3;

        alloc_(sz)
    }
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

/// Rust entry point (_start_rust)
#[doc(hidden)]
#[link_section = ".init.rust"]
#[export_name = "_start_rust"]
pub unsafe extern "C" fn start_rust(a0: u32, a1: u32, a2: u32) -> u32 {
    extern "Rust" {
        // This symbol will be provided by the user via `#[nexus_rt::main]`
        fn main(a0: u32, a1: u32, a2: u32) -> u32;
    }
    main(a0, a1, a2)
}
