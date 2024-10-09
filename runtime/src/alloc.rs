// Copyright 2023 RISC Zero, Inc.
// Copyright 2024 Nexus Laboratories, Inc.
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

// Minimum gap between heap and stack
const MEMORY_GAP: usize = 0x1000;

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn sys_alloc_aligned(bytes: usize, align: usize) -> *mut u8 {
    extern "C" {
        // https://lld.llvm.org/ELF/linker_script.html#sections-command
        static _end: u8;
    }

    // Pointer to next heap address to use, or 0 if the heap has not yet been
    // initialized.
    static mut HEAP_POS: usize = 0;

    // SAFETY: Single threaded, so nothing else can touch this while we're working.
    let mut heap_pos = HEAP_POS;

    if heap_pos == 0 {
        // check to see if vm has a different place we should expect the heap to be
        let mut overwrite: u32;
        core::arch::asm!("ecall", in("a7") 1027, out("a0") overwrite);

        if overwrite > 0 {
            heap_pos = overwrite as usize;
        } else {
            heap_pos = &_end as *const u8 as usize;
        }
    }

    let offset = heap_pos & (align - 1);
    if offset != 0 {
        heap_pos = heap_pos
            .checked_add(align - offset)
            .expect("Heap calculation has overflowed");
    }

    let ptr = heap_pos as *mut u8;
    heap_pos = heap_pos
        .checked_add(bytes)
        .expect("Heap calculation has overflowed");

    // Get the current stack pointer
    let stack_ptr: usize;
    unsafe {
        core::arch::asm!(
            "mv {}, sp",
            out(reg) stack_ptr
        );
    }

    // Check if the heap is about to clash with the stack
    let gap_check = heap_pos
        .checked_add(MEMORY_GAP)
        .expect("Heap calculation has overflowed");
    if gap_check > stack_ptr {
        panic!(
            "Heap clashing with stack (heap: 0x{:x}, stack: 0x{:x})",
            heap_pos, stack_ptr
        );
    }

    HEAP_POS = heap_pos;
    ptr
}
