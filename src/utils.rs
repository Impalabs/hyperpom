//! Miscellaneous functions used by different modules of the fuzzer.

use std::arch::asm;

// -----------------------------------------------------------------------------------------------
// Code ranges

/// A range of virtual addresses that contains instructions.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct CodeRange(pub(crate) std::ops::Range<u64>);

impl CodeRange {
    /// Creates a new code range.
    ///
    /// Since we can't just instrument everything, because of data sections found in code ranges
    /// that could be interpreted as instructions. The user is responsible for identifying which
    /// ranges are actual code ranges.
    pub fn new(start: u64, end: u64) -> Self {
        Self(start..end)
    }
}

// -----------------------------------------------------------------------------------------------
// Random generator

/// Random number generator based on the xorshift algorithm.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct Random {
    /// The seed used for random generation.
    seed: u64,
}

impl Random {
    /// Set of alphanumeric characters that can be used when generating random strings.
    const ALPHANUM: &'static str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    /// Creates a new random number generator.
    #[inline]
    pub fn new(seed: u64) -> Self {
        assert_ne!(seed, 0);
        Self { seed }
    }

    /// Splits the current random number generator into a second one in a deterministic manner.
    #[inline]
    pub fn split(&mut self) -> Self {
        Self::new(self.u64() ^ 0x43e47ca448538d19)
    }

    /// Updates the PRNG's internal seed.
    #[inline]
    fn update(&mut self) {
        self.seed ^= self.seed << 13;
        self.seed ^= self.seed >> 7;
        self.seed ^= self.seed << 17;
    }

    /// Retrieves the PRNG's state without updating it.
    #[inline]
    pub fn get_state(&self) -> u64 {
        self.seed
    }

    /// Generates a random `u64` using a uniform distribution.
    #[inline]
    pub fn u64(&mut self) -> u64 {
        self.update();
        self.seed
    }

    /// Generates a random `u64` in the range `[start; end[` using a uniform distribution.
    #[inline]
    pub fn u64_range(&mut self, start: u64, end: u64) -> Option<u64> {
        self.update();
        Some(start + self.seed % end.checked_sub(start)?)
    }

    /// Generates a random `u64` in the range `[start; end[` using an exponential distribution.
    // TODO: check start and end, make sure they are valid.
    #[inline]
    pub fn exp_range(&mut self, start: u64, end: u64) -> Option<u64> {
        self.update();
        let (start, end) = (start as f64, end as f64);
        let rand = start + (end - start) * self.seed as f64 / u64::MAX as f64;
        let (exp_start, exp_end, exp_rand) = (
            (-start / 10.0).exp(),
            (-end / 10.0).exp(),
            (-rand / 10.0).exp(),
        );
        let res = start + (end - start) * (exp_rand - exp_end) / (exp_start - exp_end);
        Some(res as u64)
    }

    /// Generates a random alphanumeric string of length `len`.
    pub fn str(&mut self, len: usize) -> String {
        (0..len).step_by(8).fold(String::new(), |s, i| {
            let size = std::cmp::min(8, len - i);
            let random = self.u64();
            (0..size).fold(s, |mut t, j| {
                let idx = ((random >> j) & 0xff) % Self::ALPHANUM.len() as u64;
                let c = Self::ALPHANUM.as_bytes()[idx as usize] as char;
                t.push(c);
                t
            })
        })
    }

    /// Generates a random vector of bytes of length `len`.
    #[allow(clippy::uninit_vec)]
    #[inline]
    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        // let len = if len % 8 != 0 { len + (8 - len % 8) } else { len };
        let mut v = Vec::with_capacity(len);
        // SAFETY: we can directly set the length, since the allocation is large enough and
        //         we fill the vector entirely, so no unitialized values will leak.
        unsafe { v.set_len(len) };
        (0..len).step_by(8).fold(v, |mut v, i| {
            let size = std::cmp::min(8, len - i);
            let random = self.u64();
            v[i..i + size].copy_from_slice(&random.to_le_bytes()[..size]);
            v
        })
    }

    /// Generates a random vector of bytes of length `len`.
    #[inline]
    pub fn bytes_into_slice(&mut self, slice: &mut [u8], offset: usize, len: usize) {
        for i in (offset..offset + len).step_by(8) {
            let size = std::cmp::min(8, offset + len - i);
            slice[i..i + size].copy_from_slice(&self.u64().to_le_bytes()[..size]);
        }
    }

    /// Crates an iterator yielding random bytes.
    #[inline]
    pub fn bytes_iter(&mut self) -> RandomBytesIterator {
        RandomBytesIterator {
            rand: self.split(),
            current: [0u8; 8],
            offset: 0,
        }
    }
}

/// Iterator yielding random bytes.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct RandomBytesIterator {
    /// The iterator's PRNG.
    rand: Random,
    /// Array from which random bytes are yielded. It contains 8 random bytes and is refilled
    /// once all values have been used.
    current: [u8; 8],
    /// The current offset in the random bytes array.
    offset: usize,
}

impl Iterator for RandomBytesIterator {
    type Item = u8;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.offset % 8 == 0 {
            self.offset = 0;
            self.current = self.rand.u64().to_le_bytes();
        }
        let b = self.current[self.offset % 8];
        self.offset += 1;
        Some(b)
    }
}

// -----------------------------------------------------------------------------------------------
// Misc functions

/// A fast log2 implementation for `usize` equivalent to `(x as f64).log2().ceil()`.
#[inline]
pub fn log2(x: usize) -> usize {
    let (orig_x, mut x, mut log) = (x, x, 0);
    while x != 0 {
        x >>= 1;
        log += 1;
    }
    log - 1 + ((orig_x & (orig_x - 1)) != 0) as usize
}

/// A fast log2 implementation for `usize` equivalent to `(x as f64).log2().floor()`.
#[inline]
pub fn log2_floor(x: usize) -> usize {
    let mut x = x;
    let mut log = 0;
    while x != 0 {
        x >>= 1;
        log += 1;
    }
    log - 1_usize
}

/// Returns the value of the Counter-timer Physical Count register (CNTPCT_EL0).
#[inline]
pub fn get_phys_counter() -> u64 {
    let mut count;
    unsafe {
        asm!(
            "mrs {}, cntpct_el0",
            out(reg) count
        );
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn utils_random_u64() {
        let mut rand = Random::new(0xa5a5a5a5a5a5a5);
        assert_eq!(
            (0..1000)
                .map(|_| rand.u64())
                .collect::<HashSet<u64>>()
                .len(),
            1000
        );
    }

    #[test]
    fn utils_random_range() {
        let mut rand = Random::new(0xa5a5a5a5a5a5a5);
        assert_eq!(
            (0..1000).all(|_| {
                let r = rand.u64_range(123, 456).unwrap();
                123 <= r && r < 456
            }),
            true
        );
    }

    #[test]
    fn utils_random_exp_range() {
        let mut rand = Random::new(0xa5a5a5a5a5a5a5);
        let mut distribution = [0; 100];
        (0..10000000).for_each(|_| {
            let r = rand.exp_range(0, distribution.len() as u64).unwrap();
            distribution[r as usize] += 1;
        });
        println!("{:?}", distribution);
    }

    #[test]
    fn utils_random_strings() {
        let mut rand = Random::new(0xa5a5a5a5a5a5a5);
        assert_eq!(
            (0..1000)
                .map(|_| rand.str(100))
                .collect::<HashSet<String>>()
                .len(),
            1000
        );
    }

    #[test]
    fn utils_random_bytes_iter() {
        let mut rand = Random::new(0xa5a5a5a5a5a5a5);
        println!("{:?}", rand.bytes_iter().take(25).collect::<Vec<u8>>());
        println!("{:?}", rand.bytes_iter().take(25).collect::<Vec<u8>>());
        println!("{:?}", rand.bytes_iter().take(25).collect::<Vec<u8>>());
        println!("{:?}", rand.bytes_iter().take(25).collect::<Vec<u8>>());
        println!("{:?}", rand.bytes_iter().take(25).collect::<Vec<u8>>());
        assert_eq!(
            (0..1000)
                .map(|_| rand.bytes_iter().take(10).collect::<Vec<u8>>())
                .collect::<HashSet<Vec<u8>>>()
                .len(),
            1000
        );
    }
}
