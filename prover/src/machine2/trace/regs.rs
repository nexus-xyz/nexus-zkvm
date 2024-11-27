use nexus_common::riscv::register::NUM_REGISTERS;

// This file contains utilities for register memory checking

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisterMemCheckSideNote {
    pub(crate) last_access_timestamp: [u32; NUM_REGISTERS],
    pub(crate) last_access_value: [u32; NUM_REGISTERS],
}

impl Default for RegisterMemCheckSideNote {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) struct AccessResult {
    pub(crate) prev_timestamp: u32,
    pub(crate) prev_value: u32,
}

impl RegisterMemCheckSideNote {
    pub fn new() -> Self {
        Self {
            last_access_timestamp: [0; NUM_REGISTERS],
            last_access_value: [0; NUM_REGISTERS],
        }
    }
    pub(crate) fn access(&mut self, reg: u32, cur_timestamp: u32, cur_value: u32) -> AccessResult {
        assert!((reg as usize) < NUM_REGISTERS);
        let ret = AccessResult {
            prev_timestamp: self.last_access_timestamp[reg as usize],
            prev_value: self.last_access_value[reg as usize],
        };
        self.last_access_timestamp[reg as usize] = cur_timestamp;
        self.last_access_value[reg as usize] = cur_value;
        ret
    }
}
