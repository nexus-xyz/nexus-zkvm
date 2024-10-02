// Nexus VM runtime environment
// Note: adapted from riscv-rt, which was adapted from cortex-m.
use crate::alloc::sys_alloc_aligned;
use core::alloc::{GlobalAlloc, Layout};
use core::panic::PanicInfo;

#[inline(never)]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    extern "C" {
        fn abort() -> !;
    }
    crate::write_log("PANIC\n");
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
        sys_alloc_aligned(layout.size(), layout.align())
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

#[no_mangle]
pub static __memory_top: u32 = 0x8040_0000;
