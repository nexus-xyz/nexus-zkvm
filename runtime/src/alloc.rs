// Copyright 2023 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
const MAX_MEMORY: usize = 0x400000; // TODO: Grab the number from default.x and jolt.x
const MEMORY_GAP: usize = 0x1000; // Minimum buffer between heap and stack

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn sys_alloc_aligned(bytes: usize, align: usize) -> *mut u8 {
    #[cfg(target_arch = "riscv32")]
    extern "C" {
        // https://lld.llvm.org/ELF/linker_script.html#sections-command
        static _end: u8;
    }

    // Pointer to next heap address to use, or 0 if the heap has not yet been
    // initialized.
    static mut HEAP_POS: usize = 0;

    // SAFETY: Single threaded, so nothing else can touch this while we're working.
    let mut heap_pos = HEAP_POS;

    #[cfg(target_arch = "riscv32")]
    if heap_pos == 0 {
        heap_pos = &_end as *const u8 as usize;
    }

    let offset = heap_pos & (align - 1);
    if offset != 0 {
        let (overflowed, heap_pos) = heap_pos.overflowing_add(align - offset);
        if overflowed {
            panic!("Heap limit exceeded")
        }
    }

    let ptr = heap_pos as *mut u8;
    let (overflowed, heap_pos) = heap_pos.overflowing_add(bytes);
    if overflowed {
        panic!("Heap limit exceeded")
    }

    // Get the current stack pointer
    let stack_ptr: usize;
    unsafe {
        asm!(
            "mv {}, sp",
            out(reg) stack_ptr
        );
    }

    // Check if the heap is about to clash with the stack
    if heap_pos + MEMORY_GAP > stack_ptr {
        panic!(
            "Heap is about to clash with stack (heap: 0x{:x}, stack: 0x{:x})",
            heap_pos, stack_ptr
        );
    }

    // Check if heap overlaps the stack memory
    if heap_pos > MAX_MEMORY {
        panic!("Heap limit exceeded (0x{:x})", MAX_MEMORY);
    }

    HEAP_POS = heap_pos;
    ptr
}
