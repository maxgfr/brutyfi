/*!
 * Numeric password generation for WPA/WPA2 bruteforce
 *
 * Optimized for parallel processing with minimal memory allocation.
 */

/// Parallel numeric password generator for efficient bruteforce
///
/// Generates numeric passwords in parallel batches with optimal
/// chunk sizing for multi-core processors.
pub struct ParallelPasswordGenerator {
    start: u64,
    end: u64,
    length: usize,
    batch_size: usize,
}

impl ParallelPasswordGenerator {
    /// Create a new parallel generator for a specific length
    ///
    /// # Arguments
    /// * `length` - Number of digits
    /// * `threads` - Number of threads (used to optimize batch size)
    pub fn new(length: usize, threads: usize) -> Self {
        let start = 0; // Always start at 0 (e.g., 00000000)
        let end = 10u64.pow(length as u32); // Full range: 10^length

        // Optimal batch size: balance between parallelism and overhead
        // Cap at 1000 to ensure UI responsiveness (updates every ~0.5s at 2000 pwd/s)
        let batch_size = 1000.min((end - start) as usize / threads);
        // Ensure at least some batch size
        let batch_size = batch_size.max(100);

        Self {
            start,
            end,
            length,
            batch_size,
        }
    }

    /// Get total number of combinations
    pub fn total_combinations(&self) -> u64 {
        self.end - self.start
    }

    /// Generate passwords in batches
    ///
    /// Returns an iterator of password batches that can be processed in parallel.
    pub fn batches(&self) -> impl Iterator<Item = Vec<String>> + '_ {
        (self.start..self.end)
            .step_by(self.batch_size)
            .map(move |batch_start| {
                let batch_end = (batch_start + self.batch_size as u64).min(self.end);
                (batch_start..batch_end)
                    .map(|num| format!("{:0width$}", num, width = self.length))
                    .collect()
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generator_basic() {
        let gen = ParallelPasswordGenerator::new(2, 4);
        assert_eq!(gen.total_combinations(), 90); // 10 to 99
        assert_eq!(gen.length, 2);
    }

    #[test]
    fn test_generator_batches() {
        let gen = ParallelPasswordGenerator::new(2, 4);
        let batches: Vec<Vec<String>> = gen.batches().collect();

        assert!(!batches.is_empty());

        // First batch should start with "10"
        assert_eq!(batches[0][0], "10");
    }

    #[test]
    fn test_generator_format() {
        let gen = ParallelPasswordGenerator::new(3, 4);
        let first_batch = gen.batches().next().unwrap();

        assert_eq!(first_batch[0], "100");
        assert_eq!(first_batch[1], "101");
        assert_eq!(first_batch[2], "102");
    }
}
