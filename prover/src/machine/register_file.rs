use rand::Rng;

use crate::machine::consts::NUM_REGISTERS;
use crate::utils::WORD_SIZE;

pub struct PrevRegister {
    pub timestamp: u32,
    pub value: [u8; WORD_SIZE],
}
#[derive(Clone, Copy, Debug)]
pub struct AddMachineRegisterFile {
    // TODO: add timestamp for register memory checking
    vals: [[u8; WORD_SIZE]; NUM_REGISTERS],
    _timestamps: [u32; NUM_REGISTERS], // TODO: force all access to modify timestamp
}

impl AddMachineRegisterFile {
    pub fn new(rng: &mut impl Rng) -> Self {
        let mut vals: [[u8; WORD_SIZE]; NUM_REGISTERS] = rng.gen();
        vals[0] = [0; WORD_SIZE]; // r0 is always zero
        let timestamps: [u32; NUM_REGISTERS] = [0; NUM_REGISTERS]; // timestamp 0 is reserved for initialization
        Self {
            vals,
            _timestamps: timestamps,
        }
    }
    pub fn read(&mut self, idx: usize, timestamp: u32) -> ([u8; WORD_SIZE], PrevRegister) {
        assert!(idx < NUM_REGISTERS);
        let prev = PrevRegister {
            timestamp: self._timestamps[idx],
            value: self.vals[idx],
        };
        self._timestamps[idx] = timestamp;
        (self.vals[idx], prev)
    }
    pub fn write(&mut self, idx: usize, val: [u8; WORD_SIZE], timestamp: u32) -> PrevRegister {
        assert!(idx < NUM_REGISTERS);
        let prev = PrevRegister {
            timestamp: self._timestamps[idx],
            value: self.vals[idx],
        };
        self._timestamps[idx] = timestamp;
        self.vals[idx] = val;
        prev
    }
}
