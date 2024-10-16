// Nexus VM runtime environment
// Note: adapted from riscv-rt, which was adapted from cortex-m.
use crate::alloc::sys_alloc_aligned;
use crate::{ecall, PANIC_ERROR_CODE, SYS_EXIT, SYS_OVERWRITE_SP};
use core::alloc::{GlobalAlloc, Layout};
use core::panic::PanicInfo;

#[inline(never)]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    let _ = ecall!(SYS_EXIT, PANIC_ERROR_CODE);
    // Ecall will trigger exit syscall, so we will never return.
    unsafe {
        core::hint::unreachable_unchecked();
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

/// Ecall to potentially overwrite stack pointer for second pass.
#[doc(hidden)]
#[link_section = ".init.rust"]
#[export_name = "_overwrite_sp"]
pub unsafe extern "C" fn overwrite_sp() {
    #[cfg(target_arch = "riscv32")]
    let _ = ecall!(SYS_OVERWRITE_SP);
}

/// Rust entry point (_start_rust).
#[doc(hidden)]
#[link_section = ".init.rust"]
#[export_name = "_start_rust"]
pub unsafe extern "C" fn start_rust(a0: u32, a1: u32, a2: u32) -> u32 {
    extern "Rust" {
        // This symbol will be provided by the user via `#[nexus_rt::main]`
        fn main(a0: u32, a1: u32, a2: u32) -> u32;
    }

    // Run the program.
    let result = main(a0, a1, a2);

    // Finish with exit syscall.
    ecall!(SYS_EXIT, result)
}

#[no_mangle]
pub static __memory_top: u32 = 0x80400000;
