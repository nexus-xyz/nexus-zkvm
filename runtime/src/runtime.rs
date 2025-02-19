// Nexus VM runtime environment
// Note: adapted from riscv-rt, which was adapted from cortex-m.
use crate::alloc::sys_alloc_aligned;
use crate::{ecall, write_output, EXIT_PANIC, EXIT_SUCCESS, SYS_EXIT};
use core::alloc::{GlobalAlloc, Layout};
use core::panic::PanicInfo;

#[inline(never)]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    // Write the exit code to the output.
    let _ = write_output!(0, EXIT_PANIC);
    // Finish with exit syscall.
    let _ = ecall!(SYS_EXIT, EXIT_PANIC);
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

/// Rust entry point (_start_rust).
#[doc(hidden)]
#[link_section = ".init.rust"]
#[export_name = "_start_rust"]
pub unsafe extern "C" fn start_rust() -> u32 {
    extern "Rust" {
        // This symbol will be provided by the user via `#[nexus_rt::main]`
        fn main();
    }

    // Run the program.
    main();

    // Write the exit code to the output.
    let _ = write_output!(0, EXIT_SUCCESS);
    // Finish with exit syscall.
    ecall!(SYS_EXIT, EXIT_SUCCESS)
}

// This globally emitted assembly ensure that we have an easy-to-work-with entrypoint for the guest
// program.
//
// The first linker directives ensure that the entrypoint (`_start`) is located at the beginning of
// the program's text section (which starts with the `.init` section due to our linker script).
core::arch::global_asm!(
    r#"
    .option nopic
    .section .init
    .global _start
    .extern __memory_top
    _start:
        .option push
        .option norelax // this option is necessary to ensure correctness
        la gp, __global_pointer$ // set in the linker script
        .option pop

        la sp, __memory_top // default to growing the stack (down) from here

        // but make an ecall to potentially overwrite it
        // we embed an ecall instruction to avoid any possibility of updating `sp` by the compiler
        // generating a function call
        li a7, 0x402 // SYS_OVERWRITE_SP
        ecall

        mv fp, sp

        jal ra, _start_rust
"#
);

#[no_mangle]
pub static __memory_top: u32 = 0x80400000;
