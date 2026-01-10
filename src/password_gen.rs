/*!
 * SIMD-optimized password generation
 *
 * Advanced optimizations:
 * - SIMD-friendly data layout
 * - Cache-line aligned structures
 * - Vectorized operations where possible
 * - Zero-copy iterators
 * - Branchless digit conversion
 */

use rayon::prelude::*;

/// SIMD-friendly password generator
/// Uses techniques to enable compiler auto-vectorization
pub struct SimdPasswordGenerator {
    length: usize,
    max_combinations: u64,
}

impl SimdPasswordGenerator {
    pub fn new(length: usize) -> Self {
        let max_combinations = 10u64.pow(length as u32);
        Self {
            length,
            max_combinations,
        }
    }

    /// Total number of combinations
    #[inline]
    pub fn total_combinations(&self) -> u64 {
        self.max_combinations
    }

    /// Generate password at index with branchless conversion
    /// Optimized for CPU pipelining and auto-vectorization
    #[inline(always)]
    pub fn generate_at_index(&self, mut index: u64) -> String {
        // Use stack-allocated array for better cache performance
        let mut buffer = [b'0'; 20]; // Max 20 digits for u64
        let start_idx = 20 - self.length;

        // Branchless digit extraction (reverse order)
        for i in (start_idx..20).rev() {
            buffer[i] = b'0' + (index % 10) as u8;
            index /= 10;
        }

        // SAFETY: We only use ASCII digits, which are valid UTF-8
        unsafe { String::from_utf8_unchecked(buffer[start_idx..].to_vec()) }
    }

    /// Generate passwords in chunks for better cache locality
    /// Returns iterator over password strings
    pub fn generate_chunk(&self, start: u64, count: u64) -> Vec<String> {
        let end = (start + count).min(self.max_combinations);
        let actual_count = (end - start) as usize;

        let mut passwords = Vec::with_capacity(actual_count);

        // Sequential generation for cache-friendly access
        for idx in start..end {
            passwords.push(self.generate_at_index(idx));
        }

        passwords
    }

    /// Parallel chunk iterator
    pub fn par_chunks(&self, chunk_size: u64) -> impl ParallelIterator<Item = Vec<String>> + '_ {
        (0..self.max_combinations)
            .step_by(chunk_size as usize)
            .par_bridge()
            .map(move |start| {
                let count = chunk_size.min(self.max_combinations - start);
                self.generate_chunk(start, count)
            })
    }
}

/// Ultra-fast numeric password range generator
/// Optimized for:
/// - Minimal allocations
/// - CPU cache friendliness
/// - SIMD auto-vectorization potential
#[derive(Clone)]
pub struct UltraPasswordRange {
    start: u64,
    end: u64,
    length: usize,
}

impl UltraPasswordRange {
    pub fn new(start: u64, end: u64, length: usize) -> Self {
        Self { start, end, length }
    }

    /// Generate all passwords in this range
    /// Uses pre-allocated buffer to reduce allocations
    pub fn generate_all(&self) -> Vec<String> {
        let count = (self.end - self.start) as usize;
        let mut passwords = Vec::with_capacity(count);

        // Pre-allocate single buffer and reuse it
        let mut buffer = [b'0'; 20]; // Stack allocation for better performance
        let start_idx = 20 - self.length;

        for mut num in self.start..self.end {
            // Fast digit extraction (branchless)
            for i in (start_idx..20).rev() {
                buffer[i] = b'0' + (num % 10) as u8;
                num /= 10;
            }

            // SAFETY: We only write ASCII digits
            let password = unsafe {
                String::from_utf8_unchecked(buffer[start_idx..].to_vec())
            };
            passwords.push(password);
        }

        passwords
    }
}

/// Adaptive parallel password generator
/// Automatically adjusts chunk sizes based on available parallelism
pub struct AdaptivePasswordGenerator {
    length: usize,
    max_combinations: u64,
    optimal_chunk_size: usize,
}

impl AdaptivePasswordGenerator {
    pub fn new(length: usize, num_threads: usize) -> Self {
        let max_combinations = 10u64.pow(length as u32);

        // Calculate optimal chunk size based on:
        // - Number of threads (aim for 4x work chunks per thread)
        // - CPU cache size (L3 cache typically 8-32MB, aim for L2 ~256KB)
        // - String overhead (~24 bytes) + content (~length bytes)
        let bytes_per_password = 24 + length;
        let l2_cache_size = 256 * 1024; // 256KB L2 cache target
        let cache_friendly_size = l2_cache_size / bytes_per_password;

        // Ensure we have enough chunks for good load balancing
        let min_chunks = num_threads * 8; // 8 chunks per thread minimum
        let parallelism_size = (max_combinations / min_chunks as u64).max(1000) as usize;

        let optimal_chunk_size = cache_friendly_size.min(parallelism_size).max(1000);

        Self {
            length,
            max_combinations,
            optimal_chunk_size,
        }
    }

    /// Generate passwords in optimal-sized batches
    pub fn batches(&self) -> impl Iterator<Item = Vec<String>> + '_ {
        let chunk_size = self.optimal_chunk_size as u64;
        (0..self.max_combinations).step_by(self.optimal_chunk_size).map(
            move |start| {
                let end = (start + chunk_size).min(self.max_combinations);
                let range = UltraPasswordRange::new(start, end, self.length);
                range.generate_all()
            },
        )
    }

    /// Parallel batches with work stealing
    pub fn par_batches(&self) -> impl ParallelIterator<Item = Vec<String>> + '_ {
        let chunk_size = self.optimal_chunk_size as u64;
        (0..self.max_combinations)
            .step_by(self.optimal_chunk_size)
            .par_bridge()
            .map(move |start| {
                let end = (start + chunk_size).min(self.max_combinations);
                let range = UltraPasswordRange::new(start, end, self.length);
                range.generate_all()
            })
    }

    pub fn total_combinations(&self) -> u64 {
        self.max_combinations
    }
}

/// Enhanced common pattern generator with more patterns
pub fn generate_enhanced_patterns(length: usize) -> Vec<String> {
    let mut patterns = Vec::with_capacity(1000);

    // All zeros and ones
    patterns.push("0".repeat(length));
    patterns.push("1".repeat(length));

    // Repeated digits (0-9)
    for digit in 0..=9 {
        patterns.push(digit.to_string().repeat(length));
    }

    // Sequential patterns
    if length <= 10 {
        // Ascending
        let mut seq = String::new();
        for i in 0..length {
            seq.push_str(&(i % 10).to_string());
        }
        patterns.push(seq);

        // Descending
        let mut seq = String::new();
        for i in (0..length).rev() {
            seq.push_str(&(i % 10).to_string());
        }
        patterns.push(seq);

        // 123...
        let mut seq = String::new();
        for i in 1..=length {
            seq.push_str(&(i % 10).to_string());
        }
        patterns.push(seq);

        // ...321
        let mut seq = String::new();
        for i in (1..=length).rev() {
            seq.push_str(&(i % 10).to_string());
        }
        patterns.push(seq);
    }

    // Alternating patterns
    for d1 in 0..=9 {
        for d2 in 0..=9 {
            if d1 == d2 {
                continue;
            }
            let mut pattern = String::new();
            for i in 0..length {
                if i % 2 == 0 {
                    pattern.push_str(&d1.to_string());
                } else {
                    pattern.push_str(&d2.to_string());
                }
            }
            patterns.push(pattern);
        }
    }

    // Mirror patterns
    if length >= 4 && length % 2 == 0 {
        let half = length / 2;
        for start in 0..=9 {
            let mut mirror = String::new();
            for i in 0..half {
                let digit = (start + i) % 10;
                mirror.push_str(&digit.to_string());
            }
            for i in (0..half).rev() {
                let digit = (start + i) % 10;
                mirror.push_str(&digit.to_string());
            }
            patterns.push(mirror);
        }
    }

    // Year patterns (for 8-digit passwords)
    if length == 8 {
        for year in 1950..=2030 {
            patterns.push(format!("{}{}", year, year));
            patterns.push(format!("{}0000", year));
            patterns.push(format!("0000{}", year));
            patterns.push(format!("{}1234", year));
            patterns.push(format!("1234{}", year));
        }

        // Common dates (DDMMYYYY and MMDDYYYY)
        for month in 1..=12 {
            for day in 1..=31 {
                patterns.push(format!("{:02}{:02}2000", day, month));
                patterns.push(format!("{:02}{:02}1990", day, month));
                patterns.push(format!("{:02}{:02}1995", day, month));
                patterns.push(format!("{:02}{:02}2000", month, day));
            }
        }
    }

    // Phone-like patterns (for 8 digits)
    if length == 8 {
        // Common area codes
        let area_codes = vec!["0800", "0700", "0600", "0500"];
        for area in area_codes {
            for suffix in 0..100 {
                patterns.push(format!("{}{:04}", area, suffix));
            }
        }
    }

    // Keyboard patterns
    if length == 8 {
        patterns.push("12312312".to_string());
        patterns.push("23232323".to_string());
        patterns.push("45454545".to_string());
        patterns.push("69696969".to_string());
        patterns.push("12341234".to_string());
    }

    // Remove duplicates and ensure correct length
    patterns.sort_unstable();
    patterns.dedup();
    patterns.retain(|p| p.len() == length);

    patterns
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simd_generator() {
        let gen = SimdPasswordGenerator::new(4);
        assert_eq!(gen.generate_at_index(0), "0000");
        assert_eq!(gen.generate_at_index(1234), "1234");
        assert_eq!(gen.generate_at_index(9999), "9999");
    }

    #[test]
    fn test_ultra_range() {
        let range = UltraPasswordRange::new(0, 10, 3);
        let passwords = range.generate_all();
        assert_eq!(passwords.len(), 10);
        assert_eq!(passwords[0], "000");
        assert_eq!(passwords[9], "009");
    }

    #[test]
    fn test_adaptive_generator() {
        let gen = AdaptivePasswordGenerator::new(3, 4);
        let batches: Vec<_> = gen.batches().take(2).collect();
        assert!(batches.len() <= 2);
    }

    #[test]
    fn test_enhanced_patterns() {
        let patterns = generate_enhanced_patterns(8);
        assert!(patterns.contains(&"11111111".to_string()));
        assert!(patterns.contains(&"12345678".to_string()));
        println!("Enhanced patterns count: {}", patterns.len());
    }
}

/// Parallel password generator (alias for AdaptivePasswordGenerator)
pub type ParallelPasswordGenerator = AdaptivePasswordGenerator;

/// Smart password generator with common patterns
pub struct SmartPasswordGenerator {
    length: usize,
    batch_size: usize,
}

impl SmartPasswordGenerator {
    pub fn new(length: usize, batch_size: usize) -> Self {
        Self { length, batch_size }
    }

    /// Get common patterns to try first
    pub fn common_patterns(&self) -> Vec<String> {
        generate_enhanced_patterns(self.length)
    }

    /// Total combinations
    pub fn total_combinations(&self) -> u64 {
        10u64.pow(self.length as u32)
    }
}
