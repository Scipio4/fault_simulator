use super::{FaultFunctions, FaultType};
use crate::{
    disassembly::Disassembly,
    simulation::{
        cpu::Cpu,
        fault_data::FaultData,
        record::{FaultRecord, TraceRecord},
    },
};
use std::fmt::Debug;
use std::sync::Arc;

/// Instruction bitflip fault structure
///
#[derive(Clone, Copy)]
pub struct InstructionBitFlip {
    pub xor_value: u32,
}

impl Debug for InstructionBitFlip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "InstructionBitFlip(insbf_{:08x})", self.xor_value)
    }
}

/// Implementation for InstructionBitFlip fault
impl InstructionBitFlip {
    /// Create a new InstructionBitFlip fault
    pub fn new(xor_value: u32) -> Arc<Self> {
        Arc::new(Self { xor_value })
    }
}

impl FaultFunctions for InstructionBitFlip {
    /// Execute a InstructionBitFlip xor opcode with xor_value.
    fn execute(&self, cpu: &mut Cpu, fault: &FaultRecord) {
        let address = cpu.get_program_counter();
        let cmd_size = cpu.get_asm_cmd_size(address).unwrap();

        // Read assembler line
        let mut original_instruction = vec![0; cmd_size];
        // Read original instructions
        cpu.memory_read(address, &mut original_instruction).unwrap();

        // Convert byte vector into one word
        let ins_word = match original_instruction.as_slice() {
            [a, b] => u32::from_le_bytes([*a, *b, 0, 0]),
            [a, b, c, d] => u32::from_le_bytes([*a, *b, *c, *d]),
            _ => panic!("Instruction must have either 2 or 4 bytes"),
        };

        let modified_ins = ins_word ^ self.xor_value;

        // Convert the u32 back to vec
        let mut modified_instruction: Vec<u8> = modified_ins.to_le_bytes().to_vec();
        // Truncate vec to cmd_size, removes leading zeros in case of 16bit instructions
        modified_instruction.truncate(cmd_size);

        // Perform modified instruction and restore original instruction afterwards
        // Otherwise fault is persistent
        // ToDo: This conflicts with general logic implemented in run_with_faults() if double glitches are simulated
        cpu.memory_write(address, &modified_instruction).unwrap();
        let _ = cpu.run_steps(1, false);
        cpu.memory_write(address, &original_instruction).unwrap();

        let record = TraceRecord::Fault {
            address,
            fault_type: format!(
                "Instruction BitFlip (Value: {:08x}) 0x{:08x} -> 0x{:08x}",
                self.xor_value, ins_word, modified_ins,
            ),
        };
        cpu.get_trace_data().push(record.clone());

        // Push to fault data vector
        cpu.get_fault_data().push(FaultData {
            original_instructions: original_instruction,
            record,
            fault: fault.clone(),
        });
    }

    /// Filtering of traces to reduce the number of traces to analyze
    fn filter(&self, records: &mut Vec<TraceRecord>, cs: &Disassembly) {
        let instruction_size = if (self.xor_value >> 16) == 0 { 2 } else { 4 } as usize;
        records.retain(|record| match record {
            TraceRecord::Instruction {
                address,
                asm_instruction,
                ..
            } => cs.get_instruction_size(asm_instruction, *address) == instruction_size,
            // Check self.xor_value bit position and instruction size
            _ => false,
        });
    }

    /// Try to parse a InstructionBitFlip fault from a string
    fn try_from(&self, input: &str) -> Option<FaultType> {
        // divide name from attribute
        let collect: Vec<&str> = input.split('_').collect();
        // check if name and attribute are present
        let fault_type = collect.first().copied()?;
        let attribute = collect.get(1).copied()?;

        if fault_type == "insbf" {
            if let Ok(xor_value) = u32::from_str_radix(attribute, 16) {
                // return Glitch struct
                return Some(Self::new(xor_value));
            }
        }
        None
    }
    /// Get the list of possible/good faults
    fn get_list(&self) -> Vec<String> {
        let mut list = Vec::new();

        for index in 0..=31 {
            list.push(format!("insbf_{:08x}", 1 << index));
        }
        list
    }
}
