//! Mutation engine implementation.

use crate::loader::Loader;
use crate::utils::*;

// -----------------------------------------------------------------------------------------------
// Mutator - Magic values

/// An array of interesting "magic" values.
pub const MAGIC_VALUES: &[&[u8]] = &[
    &[0x00],
    &[0x01],
    &[0x7f],
    &[0x80],
    &[0xff],
    &[0x00, 0x00],
    &[0x00, 0x01],
    &[0x00, 0x7f],
    &[0x00, 0x80],
    &[0xff, 0xff],
    &[0x00, 0x00, 0x00, 0x00],
    &[0x00, 0x00, 0x00, 0x01],
    &[0x00, 0x00, 0x00, 0x7f],
    &[0x00, 0x00, 0x00, 0x80],
    &[0xff, 0xff, 0xff, 0xff],
    &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
    &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f],
    &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80],
    &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
];

// -----------------------------------------------------------------------------------------------
// Mutator - Core

/// The mutator engine used to mutate testcases randomly.
///
/// # Role of the Mutator in the Fuzzer.
///
/// Since this fuzzer is mutation-based, each testcase, before being run, is mutated. The idea is
/// to take an existing testcase and alter it. The changes introduced should be small enough to
/// prevent the program from outright rejecting the testcase, but sufficient to explore new paths.
///
/// This mutator implements basic mutation strategies:
///
///  * bitflips;
///  * add, subtract, xor and negate operations on 8/16/32/64 bits of data;
///  * magic values insertion and overwrite;
///  * random values insertion and overwrite;
///  * 1-byte repetitions insertion and overwrite;
///  * shrinking and extension.
///
/// These methods are called randomly but are given arbitrary weights to prevent expensive
/// operations from being called too often (refer to the source code of [`Mutator::mutate`] for
/// more information). In the future, these weights might be changed or made user-controllable.
///
/// # Example
///
/// ```rust
/// // Creates a new random generator.
/// let rand = Random::new(0xa5a5a5a5a5a5a5);
///
/// // Creates a new mutator.
/// let mut mutator = Mutator::new(rand);
///
/// // The data to mutate
/// let mut data = vec![0x42, 0x42, 0x42, 0x42];
///
/// // Mutations
/// mutator.bitflip(&mut data, 0x100);
/// mutator.byte_op(&mut data, 0x100);
/// mutator.extend(&mut data, 0x100);
/// mutator.shrink(&mut data, 0x100);
/// mutator.magic_replace(&mut data, 0x100);
/// mutator.magic_insert(&mut data, 0x100);
/// mutator.random_replace(&mut data, 0x100);
/// mutator.random_insert(&mut data, 0x100);
/// mutator.repetition_replace(&mut data, 0x100);
/// mutator.repetition_insert(&mut data, 0x100);
/// ```
pub struct Mutator {
    pub rand: Random,
}

impl Mutator {
    /// Creates a new mutator from a PRNG.
    pub fn new(rand: Random) -> Self {
        Self { rand }
    }

    /// Randomly mutates a testcase.
    #[inline]
    pub fn mutate<L: Loader>(
        &mut self,
        loader: &L,
        data: &mut Vec<u8>,
        max_size: usize,
        max_mutations: usize,
    ) -> u64 {
        // Gets the current PRNG state to return it at the end of the function. It will be used
        // as part of the testcase's name if it produces new coverage paths.
        let prng_state = self.rand.get_state();
        // Mutating the testcase passed by the fuzzer using the implementation from the loader.
        loader.mutate(self, data, max_size, max_mutations);
        prng_state
    }

    /// Performs a bitflip of 1, 2, 3 or 4 bits at a random location in the testcase.
    #[inline]
    pub fn bitflip(&mut self, data: &mut Vec<u8>, _: usize) {
        // If the testcase is empty, there's not much we can do but return.
        if data.is_empty() {
            return;
        }
        // [idx: 63-7][size: 6-3][bit_idx: 2-0]
        let rand = self.rand.u64() as usize;
        let idx = (rand >> 7) % data.len();
        let size = (rand >> 3) & 0xf;
        let bit_idx = rand & 0x7;
        match size {
            // 8/16 chance for a 1-bit bitflip
            0x0..0x8 => data[idx] ^= 0b0001 << bit_idx,
            // 5/16 chance for a 2-bit bitflip
            0x8..0xd => data[idx] ^= 0b0011 << bit_idx,
            // 2/16 chance for a 3-bit bitflip
            0xd..0xf => data[idx] ^= 0b0111 << bit_idx,
            // 1/16 chance for a 4-bit bitflip
            0xf => data[idx] ^= 0b1111 << bit_idx,
            _ => unreachable!(),
        }
    }

    /// Adds, subtracts, XORs or negates bytes in the testcase with random values.
    #[inline]
    pub fn byte_op(&mut self, data: &mut Vec<u8>, _: usize) {
        // If the testcase is empty, there's not much we can do but return.
        if data.is_empty() {
            return;
        }
        // [idx: 63-38][size: 37-34][op: 33-32][val: 31-0]
        let rand = self.rand.u64() as usize;
        let val = rand as u32;
        let op = (rand >> 32) & 0x3;
        // Extracts the size's bit representation from the random value and check that we have
        // enough room in the testcase buffer for an operation of this size.
        let mut size_bits = (rand >> 34) & 0xf;
        let mut size = 1 << size_bits;
        if data.len() < size {
            size_bits = log2_floor(data.len());
            size = 1 << size_bits;
        }
        // Gets the location in the testcase buffer where the operation will be performed.
        let idx = (rand >> 36) % (data.len() - size + 1);
        match size_bits {
            // 8/16 chance for an 8-bit operation.
            0x0..0x8 => {
                let val = val as u8;
                match op {
                    0b00 => data[idx] = data[idx].wrapping_add(val),
                    0b01 => data[idx] = data[idx].wrapping_sub(val),
                    0b10 => data[idx] ^= val,
                    0b11 => data[idx] = !data[idx],
                    _ => unreachable!(),
                };
            }
            // 5/16 chance for a 16-bit operation.
            0x8..0xd => {
                let val = val as u16;
                let in_value = u16::from_le_bytes(data[idx..idx + 2].try_into().unwrap());
                let out_value = match op {
                    0b00 => in_value.wrapping_add(val),
                    0b01 => in_value.wrapping_sub(val),
                    0b10 => in_value ^ val,
                    0b11 => !in_value,
                    _ => unreachable!(),
                };
                data[idx..idx + 2].copy_from_slice(&out_value.to_le_bytes());
            }
            // 3/16 chance for a 32-bit operation.
            0xd..0xf => {
                let val = val as u32;
                let in_value = u32::from_le_bytes(data[idx..idx + 4].try_into().unwrap());
                let out_value = match op {
                    0b00 => in_value.wrapping_add(val),
                    0b01 => in_value.wrapping_sub(val),
                    0b10 => in_value ^ val,
                    0b11 => !in_value,
                    _ => unreachable!(),
                };
                data[idx..idx + 4].copy_from_slice(&out_value.to_le_bytes());
            }
            // 1/16 chance for a 64-bit operation.
            0xf => {
                let val = self.rand.u64();
                let in_value = u64::from_le_bytes(data[idx..idx + 8].try_into().unwrap());
                let out_value = match op {
                    0b00 => in_value.wrapping_add(val),
                    0b01 => in_value.wrapping_sub(val),
                    0b10 => in_value ^ val,
                    0b11 => !in_value,
                    _ => unreachable!(),
                };
                data[idx..idx + 8].copy_from_slice(&out_value.to_le_bytes());
            }
            _ => unreachable!(),
        };
    }

    /// Extends a testcase with a random amount of null bytes.
    #[inline]
    pub fn extend(&mut self, data: &mut Vec<u8>, max_size: usize) {
        // [idx: 63-34][extend_size: 33-5][extend_type: 4-1][idx_type: 0]
        let rand = self.rand.u64() as usize;
        let idx = if data.is_empty() {
            0
        } else {
            let idx_type = rand & 1;
            match idx_type {
                // 1/2 chance to extend from the end.
                0 => data.len(),
                // 1/2 chance to extend from a random position in the testcase.
                1 => (rand >> 34) % data.len(),
                _ => unreachable!(),
            }
        };
        // Computes the maximum size we could extend with.
        let remaining_size = max_size
            .checked_sub(data.len())
            .unwrap_or_else(|| panic!("max_size={:#x}, data_len={:#x}", max_size, data.len()));
        if remaining_size == 0 {
            return;
        }
        // Computes the extension size.
        let extend_size = (rand >> 5) & 0x1fffffff;
        let extend_type = (rand >> 1) & 0xf;
        let extend_size = match extend_type {
            // 8/16 chance to extend by 4 bytes.
            x if (0x0..0x8).contains(&x) && remaining_size >= 4 => 4,
            // 5/16 chance to extend by 8 bytes.
            x if (0x8..0xd).contains(&x) && remaining_size >= 8 => 8,
            // 3/16 chance to extend by 16 bytes.
            x if (0xd..0xf).contains(&x) && remaining_size >= 16 => 16,
            // 1/16 chance to extend by a random amount.
            _ => extend_size % (remaining_size + 1),
        };
        // Extends the buffer with null bytes.
        let extend_iter = std::iter::repeat(0u8).take(extend_size);
        data.splice(idx..idx, extend_iter);
        assert!(data.len() <= max_size);
    }

    /// Shrinks a testcase by a random amount.
    #[inline]
    pub fn shrink(&mut self, data: &mut Vec<u8>, _max_size: usize) {
        // If the testcase is empty, there's not much we can do but return.
        if data.is_empty() {
            return;
        }
        // [idx: 63-34][shrink_size: 33-5][shrink_type: 4-1][idx_type: 0]
        let rand = self.rand.u64() as usize;
        // Computes the shrinkage size.
        let shrink_size = (rand >> 5) & 0x1fffffff;
        let shrink_type = (rand >> 1) & 0xf;
        let shrink_size = match shrink_type {
            // 8/16 chance to shrink by 4 bytes.
            x if (0x0..0x8).contains(&x) && data.len() > 4 => 4,
            // 5/16 chance to shrink by 8 bytes.
            x if (0x8..0xd).contains(&x) && data.len() > 8 => 8,
            // 3/16 chance to shrink by 16 bytes.
            x if (0xd..0xf).contains(&x) && data.len() > 16 => 16,
            // 1/16 chance to shrink by a random amount.
            _ => shrink_size % data.len(),
        };
        // Computes the index from which the testcase should be shrunk.
        let idx_type = rand & 1;
        let idx = match idx_type {
            // 1/2 chance to shrink from the end.
            0 => data.len() - shrink_size,
            // 1/2 chance to shrink from a random position in the testcase.
            1 => (rand >> 34) % (data.len() - shrink_size),
            _ => unreachable!(),
        };
        // Shrinks the buffer.
        data.drain(idx..idx + shrink_size);
    }

    /// Replaces bytes at a random position with a magic value.
    #[inline]
    pub fn magic_replace(&mut self, data: &mut Vec<u8>, _max_size: usize) {
        // If the testcase is empty, there's not much we can do but return.
        if data.is_empty() {
            return;
        }
        // [i_idx: 63-8][magic_idx: 7-0]
        let rand = self.rand.u64() as usize;
        let i_idx = (rand >> 8) % data.len();
        let magic_idx = (rand & 0xff) % MAGIC_VALUES.len();
        let magic = MAGIC_VALUES[magic_idx];
        // Computes the maximum size that can be written into the testcase from index `idx`.
        let max_size = std::cmp::min(magic.len(), data.len() - i_idx);
        // Replaces the bytes by our magic value in the testcase.
        data[i_idx..i_idx + max_size].copy_from_slice(&magic[..max_size]);
    }

    /// Inserts a magic value at a random position.
    #[inline]
    pub fn magic_insert(&mut self, data: &mut Vec<u8>, max_size: usize) {
        // [idx: 63-8][magic_idx: 7-0]
        let rand = self.rand.u64() as usize;
        let i_idx = if !data.is_empty() {
            (rand >> 8) % data.len()
        } else {
            0
        };
        let magic_idx = (rand & 0xff) % MAGIC_VALUES.len();
        let magic = MAGIC_VALUES[magic_idx];
        // Computes the maximum size we could extend with.
        let remaining_size = max_size
            .checked_sub(data.len())
            .unwrap_or_else(|| panic!("max_size={:#x}, data_len={:#x}", max_size, data.len()));
        if remaining_size == 0 {
            return;
        }
        // Computes the maximum size that can be written into the testcase.
        let i_size = std::cmp::min(magic.len(), remaining_size);
        // Inserts our magic value's bytes into the testcase.
        data.splice(i_idx..i_idx, magic[..i_size].iter().copied());
        assert!(data.len() <= max_size);
    }

    /// Replaces bytes at a random position with random bytes.
    #[inline]
    pub fn random_replace(&mut self, data: &mut Vec<u8>, _max_size: usize) {
        // If the testcase is empty, there's not much we can do but return.
        if data.is_empty() {
            return;
        }
        // [r_idx: 63-34][r_size: 33-4][r_type: 3-0]
        let rand = self.rand.u64() as usize;
        let r_idx = (rand >> 34) % data.len();
        let r_size = (rand >> 4) & 0x3fff_ffff;
        let r_type = rand & 0xf;
        let r_size = match r_type {
            // 8/16 chance for a 1-byte replacement.
            0x0..0x8 => 1,
            // 4/16 chance for a 2-byte replacement.
            0x8..0xc => 2,
            // 2/16 chance for a 4-byte replacement.
            0xc..0xe => 4,
            // 1/16 chance for an 8-byte replacement.
            0xe => 8,
            // 1/16 chance to replace by a random amount.
            0xf => r_size % data.len(),
            _ => unreachable!(),
        };
        let max_size = std::cmp::min(r_size, data.len() - r_idx);
        self.rand.bytes_into_slice(data, r_idx, max_size);
    }

    /// Inserts random bytes at a random position.
    #[inline]
    pub fn random_insert(&mut self, data: &mut Vec<u8>, max_size: usize) {
        // [i_idx: 63-34][i_size: 33-4][i_type: 3-0]
        let rand = self.rand.u64() as usize;
        let i_idx = if !data.is_empty() {
            (rand >> 34) % data.len()
        } else {
            0
        };
        let i_size = (rand >> 4) & 0x3fff_ffff;
        let i_type = rand & 0xf;
        // Computes the maximum size we could extend with.
        let remaining_size = max_size
            .checked_sub(data.len())
            .unwrap_or_else(|| panic!("max_size={:#x}, data_len={:#x}", max_size, data.len()));
        if remaining_size == 0 {
            return;
        }
        let i_size = match i_type {
            // 8/16 chance for a 1-byte insertion.
            0x0..0x8 => 1,
            // 4/16 chance for a 2-byte insertion.
            0x8..0xc => 2,
            // 2/16 chance for a 4-byte insertion.
            0xc..0xe => 4,
            // 1/16 chance for an 8-byte insertion.
            0xe => 8,
            // 1/16 chance to insert a random amount of bytes.
            0xf => i_size % remaining_size,
            _ => unreachable!(),
        };
        let i_size = std::cmp::min(i_size, remaining_size);
        data.splice(i_idx..i_idx, self.rand.bytes(i_size));
        assert!(data.len() <= max_size);
    }

    /// Replaces all bytes in a random range by the same byte.
    #[inline]
    pub fn repetition_replace(&mut self, data: &mut Vec<u8>, _max_size: usize) {
        // If the testcase is empty, there's not much we can do but return.
        if data.is_empty() {
            return;
        }
        // [r_idx: 63-38][r_size: 37-12][r_byte: 11-4][r_type: 3-0]
        let rand = self.rand.u64() as usize;
        let r_idx = (rand >> 38) % data.len();
        let r_size = (rand >> 12) & 0x3ff_ffff;
        let r_byte = (rand >> 4) as u8;
        let r_type = rand & 0xf;
        let r_size = match r_type {
            // 8/16 chance for a 1-byte replacement.
            0x0..0x8 => 1,
            // 4/16 chance for a 2-byte replacement.
            0x8..0xc => 2,
            // 2/16 chance for a 4-byte replacement.
            0xc..0xe => 4,
            // 1/16 chance for an 8-byte replacement.
            0xe => 8,
            // 1/16 chance to replace by a random amount.
            0xf => r_size % data.len(),
            _ => unreachable!(),
        };
        let max_size = std::cmp::min(r_size, data.len() - r_idx);
        data[r_idx..r_idx + max_size].copy_from_slice(&vec![r_byte; max_size]);
    }

    /// Inserts a repetition of the same byte at a random position.
    #[inline]
    pub fn repetition_insert(&mut self, data: &mut Vec<u8>, max_size: usize) {
        // If the testcase is empty, there's not much we can do but return.
        if data.is_empty() {
            return;
        }
        // [i_idx: 63-38][i_size: 37-12][i_byte: 11-4][i_type: 3-0]
        let rand = self.rand.u64() as usize;
        let i_idx = if !data.is_empty() {
            (rand >> 38) % data.len()
        } else {
            0
        };
        let i_size = (rand >> 12) & 0x3ff_ffff;
        let i_byte = (rand >> 4) as u8;
        let i_type = rand & 0xf;
        // Computes the maximum size we could extend with.
        let remaining_size = max_size
            .checked_sub(data.len())
            .unwrap_or_else(|| panic!("max_size={:#x}, data_len={:#x}", max_size, data.len()));
        if remaining_size == 0 {
            return;
        }
        let i_size = match i_type {
            // 8/16 chance for a 1-byte insertion.
            0x0..0x8 => 1,
            // 4/16 chance for a 2-byte insertion.
            0x8..0xc => 2,
            // 2/16 chance for a 4-byte insertion.
            0xc..0xe => 4,
            // 1/16 chance for an 8-byte insertion.
            0xe => 8,
            // 1/16 chance to insert a random amount of bytes.
            0xf => i_size % remaining_size,
            _ => unreachable!(),
        };
        let i_size = std::cmp::min(i_size, remaining_size);
        data.splice(i_idx..i_idx, std::iter::repeat(i_byte).take(i_size));
        assert!(data.len() <= max_size);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutator_bitflip() {
        let rand = Random::new(0xa5a5a5a5a5a5a5);
        let mut mutator = Mutator::new(rand);
        let mut data = vec![0x42, 0x42, 0x42, 0x42];
        mutator.bitflip(&mut data, 0x100);
        println!("bitflip = {:?}", data);
        mutator.bitflip(&mut data, 0x100);
        println!("bitflip = {:?}", data);
        mutator.bitflip(&mut data, 0x100);
        println!("bitflip = {:?}", data);
        mutator.bitflip(&mut data, 0x100);
        println!("bitflip = {:?}", data);
        mutator.bitflip(&mut data, 0x100);
        println!("bitflip = {:?}", data);
    }

    #[test]
    fn mutator_byte_operations() {
        let rand = Random::new(0xa5a5a5a5a5a5a5);
        let mut mutator = Mutator::new(rand);
        let mut data = vec![0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42];
        mutator.byte_op(&mut data, 0x100);
        println!("byte_op = {:?}", data);
        mutator.byte_op(&mut data, 0x100);
        println!("byte_op = {:?}", data);
        mutator.byte_op(&mut data, 0x100);
        println!("byte_op = {:?}", data);
        mutator.byte_op(&mut data, 0x100);
        println!("byte_op = {:?}", data);
        mutator.byte_op(&mut data, 0x100);
        println!("byte_op = {:?}", data);
    }

    #[test]
    fn mutator_extend_shrink() {
        let rand = Random::new(0xa5a5a5a5a5a5a5);
        let mut mutator = Mutator::new(rand);
        let mut data = vec![0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42];
        mutator.extend(&mut data, 0x100);
        println!("extend = {:?}", data);
        mutator.shrink(&mut data, 0x100);
        println!("shrink = {:?}", data);
        mutator.extend(&mut data, 0x100);
        println!("extend = {:?}", data);
        mutator.shrink(&mut data, 0x100);
        println!("shrink = {:?}", data);
        mutator.extend(&mut data, 0x100);
        println!("extend = {:?}", data);
        mutator.shrink(&mut data, 0x100);
        println!("shrink = {:?}", data);
        mutator.extend(&mut data, 0x100);
        println!("extend = {:?}", data);
        mutator.shrink(&mut data, 0x100);
        println!("shrink = {:?}", data);
        mutator.extend(&mut data, 0x100);
        println!("extend = {:?}", data);
        mutator.shrink(&mut data, 0x100);
        println!("shrink = {:?}", data);
    }

    #[test]
    fn mutator_magic_replace() {
        let rand = Random::new(0xa5a5a5a5a5a5a5);
        let mut mutator = Mutator::new(rand);
        let mut data = vec![0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42];
        mutator.magic_replace(&mut data, 0x100);
        println!("magic_replace = {:?}", data);
        mutator.magic_replace(&mut data, 0x100);
        println!("magic_replace = {:?}", data);
        mutator.magic_replace(&mut data, 0x100);
        println!("magic_replace = {:?}", data);
        mutator.magic_replace(&mut data, 0x100);
        println!("magic_replace = {:?}", data);
        mutator.magic_replace(&mut data, 0x100);
        println!("magic_replace = {:?}", data);
    }

    #[test]
    fn mutator_magic_insert() {
        let rand = Random::new(0xa5a5a5a5a5a5a5);
        let mut mutator = Mutator::new(rand);
        let mut data = vec![0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42];
        mutator.magic_insert(&mut data, 0x100);
        println!("magic_insert = {:?}", data);
        mutator.magic_insert(&mut data, 0x100);
        println!("magic_insert = {:?}", data);
        mutator.magic_insert(&mut data, 0x100);
        println!("magic_insert = {:?}", data);
        mutator.magic_insert(&mut data, 0x100);
        println!("magic_insert = {:?}", data);
        mutator.magic_insert(&mut data, 0x100);
        println!("magic_insert = {:?}", data);
    }

    #[test]
    fn mutator_random_replace() {
        let rand = Random::new(0xa5a5a5a5a5a5a5);
        let mut mutator = Mutator::new(rand);
        let mut data = vec![0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42];
        mutator.random_replace(&mut data, 0x100);
        println!("random_replace = {:?}", data);
        mutator.random_replace(&mut data, 0x100);
        println!("random_replace = {:?}", data);
        mutator.random_replace(&mut data, 0x100);
        println!("random_replace = {:?}", data);
        mutator.random_replace(&mut data, 0x100);
        println!("random_replace = {:?}", data);
        mutator.random_replace(&mut data, 0x100);
        println!("random_replace = {:?}", data);
    }

    #[test]
    fn mutator_random_insert() {
        let rand = Random::new(0xa5a5a5a5a5a5a5);
        let mut mutator = Mutator::new(rand);
        let mut data = vec![0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42];
        mutator.random_insert(&mut data, 0x100);
        println!("random_insert = {:?}", data);
        mutator.random_insert(&mut data, 0x100);
        println!("random_insert = {:?}", data);
        mutator.random_insert(&mut data, 0x100);
        println!("random_insert = {:?}", data);
        mutator.random_insert(&mut data, 0x100);
        println!("random_insert = {:?}", data);
        mutator.random_insert(&mut data, 0x100);
        println!("random_insert = {:?}", data);
    }

    #[test]
    fn mutator_repetition_replace() {
        let rand = Random::new(0xa5a5a5a5a5a5a5);
        let mut mutator = Mutator::new(rand);
        let mut data = vec![0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42];
        mutator.repetition_replace(&mut data, 0x100);
        println!("repetition_replace = {:?}", data);
        mutator.repetition_replace(&mut data, 0x100);
        println!("repetition_replace = {:?}", data);
        mutator.repetition_replace(&mut data, 0x100);
        println!("repetition_replace = {:?}", data);
        mutator.repetition_replace(&mut data, 0x100);
        println!("repetition_replace = {:?}", data);
        mutator.repetition_replace(&mut data, 0x100);
        println!("repetition_replace = {:?}", data);
    }

    #[test]
    fn mutator_repetition_insert() {
        let rand = Random::new(0xa5a5a5a5a5a5a5);
        let mut mutator = Mutator::new(rand);
        let mut data = vec![0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42];
        mutator.repetition_insert(&mut data, 0x100);
        println!("repetition_insert = {:?}", data);
        mutator.repetition_insert(&mut data, 0x100);
        println!("repetition_insert = {:?}", data);
        mutator.repetition_insert(&mut data, 0x100);
        println!("repetition_insert = {:?}", data);
        mutator.repetition_insert(&mut data, 0x100);
        println!("repetition_insert = {:?}", data);
        mutator.repetition_insert(&mut data, 0x100);
        println!("repetition_insert = {:?}", data);
    }
}
