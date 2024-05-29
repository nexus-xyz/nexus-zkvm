use nexus_riscv::{
    eval::{add32, eval_inst, VM as NexusVM},
    rv32::{parse::parse_inst, Inst, RV32},
};
use nexus_vm::{instructions::Width, memory::Memory};

use jolt_common::rv_trace as jolt_rv;

use crate::{convert, Error, LOG_TARGET, VM};

/// Trace VM execution in Jolt format.
pub fn trace(vm: VM) -> Result<Vec<jolt_rv::RVTraceRow>, Error> {
    let VM { mut vm, insts, .. } = vm;

    let mut trace = Vec::new();
    loop {
        // decode next inst
        let slice = vm.mem.load(Width::W, vm.regs.pc)?.0.to_le_bytes();
        let next_inst = parse_inst(vm.regs.pc, &slice)?;
        if next_inst.inst == RV32::UNIMP {
            break;
        }

        // save store address for memory state
        let store_addr: Option<(Width, u32)> =
            if let RV32::STORE { rs1, imm, sop, .. } = next_inst.inst {
                use nexus_riscv::rv32::SOP::*;
                let width = match sop {
                    SB => Width::BU,
                    SH => Width::HU,
                    SW => Width::W,
                };

                let x = vm.get_reg(rs1);
                let addr = add32(x, imm);
                Some((width, addr))
            } else {
                None
            };

        let inst = convert::inst(next_inst);
        let mut rv_row = init_trace_row(&vm, next_inst, &inst);

        eval_inst(&mut vm)?;
        update_row_post_eval(&vm, &mut rv_row, store_addr);

        trace.push(rv_row);
    }

    tracing::debug!(
        target: LOG_TARGET,
        "Finished VM execution, trace len = {}, bytecode len = {}",
        trace.len(),
        insts.len(),
    );

    Ok(trace)
}

fn init_trace_row(
    vm: &NexusVM,
    inst: Inst,
    elf_inst: &jolt_rv::ELFInstruction,
) -> jolt_rv::RVTraceRow {
    jolt_rv::RVTraceRow {
        instruction: elf_inst.clone(),
        register_state: jolt_rv::RegisterState {
            rs1_val: elf_inst.rs1.map(|rs1| vm.get_reg(rs1 as u32) as u64),
            rs2_val: elf_inst.rs2.map(|rs2| vm.get_reg(rs2 as u32) as u64),
            rd_post_val: None,
        },
        memory_state: memory_state(vm, inst),
    }
}

fn update_row_post_eval(
    vm: &NexusVM,
    rv_trace_row: &mut jolt_rv::RVTraceRow,
    store_addr: Option<(Width, u32)>,
) {
    if let Some(rd) = rv_trace_row.instruction.rd {
        rv_trace_row.register_state.rd_post_val = Some(vm.get_reg(rd as u32) as u64);
    }
    if let Some((width, store_addr)) = store_addr {
        let new_value = vm.mem.load(width, store_addr).expect("invalid store").0 as u64;
        let Some(jolt_rv::MemoryState::Write { post_value, .. }) = &mut rv_trace_row.memory_state
        else {
            panic!("invalid memory state for store instruction");
        };
        *post_value = new_value;
    }
}

fn memory_state(vm: &NexusVM, inst: Inst) -> Option<jolt_rv::MemoryState> {
    match inst.inst {
        RV32::LOAD { rs1, imm, lop, .. } => {
            use nexus_riscv::rv32::LOP::*;
            let width = match lop {
                LB | LBU => Width::BU,
                LH | LHU => Width::HU,
                LW => Width::W,
            };
            let x = vm.get_reg(rs1);
            let addr = add32(x, imm);
            let value = vm.mem.load(width, addr).expect("invalid load").0 as u64;

            Some(jolt_rv::MemoryState::Read { address: addr as u64, value })
        }
        RV32::STORE { rs1, imm, .. } => {
            let x = vm.get_reg(rs1);
            let addr = add32(x, imm);

            Some(jolt_rv::MemoryState::Write {
                address: addr as u64,
                post_value: 0, // updated after `eval_inst`
            })
        }
        _ => None,
    }
}
