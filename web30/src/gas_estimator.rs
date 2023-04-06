//! This file contains a gas estimator struct one that can be generally used in any case where
//! waiting for lower than average gas prices is an advantage.
use crate::client::Web3;
use clarity::Uint256;
use std::cmp::Ordering;
use std::collections::VecDeque;
use std::time::Instant;

/// internal storage type for the GasTracker struct right now the
/// sample_time is only used for stale identification but it should
/// be generally useful in improving accuracy elsewhere
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GasPriceEntry {
    pub sample_time: Instant,
    pub sample: Uint256,
}

impl GasPriceEntry {
    /// Creates a new GasPriceEntry with sample_time now()
    pub fn new(sample: Uint256) -> Self {
        GasPriceEntry {
            sample_time: Instant::now(),
            sample,
        }
    }
}

// implement ord ignoring sample_time
impl Ord for GasPriceEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        let size1 = &self.sample;
        let size2 = &other.sample;
        if size1 < size2 {
            return Ordering::Less;
        }
        if size1 > size2 {
            return Ordering::Greater;
        }
        Ordering::Equal
    }
}

// boilerplate partial ord impl using above Ord
impl PartialOrd for GasPriceEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A struct for storing gas prices and estimating when it's a good
/// idea to perform some gas intensive operation
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GasTracker {
    history: VecDeque<GasPriceEntry>,
    size: usize,
}

impl GasTracker {
    /// create a new gas tracker with size
    /// internal sample size and number of samples before which
    /// it will not give an estimate
    pub fn new(size: usize) -> Self {
        GasTracker {
            history: VecDeque::new(),
            size,
        }
    }

    /// Returns the current number of stored gas prices
    pub fn get_current_size(&self) -> usize {
        self.history.len()
    }

    /// Returns a copy of the stored gas price history
    pub fn get_history(&self) -> VecDeque<GasPriceEntry> {
        self.history.clone()
    }

    /// Increases the history size limit
    /// returns an error if the history is already larger than the input size
    pub fn expand_history_size(&mut self, size: usize) {
        if self.history.len() > size {
            return;
        }
        self.size = size;
    }

    /// Gets the most recently stored gas price
    pub fn latest_gas_price(&self) -> Option<Uint256> {
        self.history.front().map(|price| price.sample)
    }

    /// Samples Ethereum gas prices and creates a new GasPriceEntry on success
    /// If you are not running GasTracker multi-threaded, consider sample_and_update()
    pub async fn sample(web30: &Web3) -> Option<GasPriceEntry> {
        match web30.eth_gas_price().await {
            Ok(price) => Some(GasPriceEntry::new(price)),
            Err(e) => {
                warn!("Unable to sample gas prices with: {:?}", e);
                None
            }
        }
    }

    /// Updates the latest gas price and adds it to the array
    /// To obtain a sample, use GasTracker::sample(), or use sample_and_update() if
    /// you are not running the GasTracker multi-threaded
    pub fn update(&mut self, sample: GasPriceEntry) {
        match self.history.len().cmp(&self.size) {
            Ordering::Less => {
                self.history.push_front(sample);
            }
            Ordering::Equal => {
                //vec is full, remove oldest entry
                self.history.pop_back();
                self.history.push_front(sample);
            }
            Ordering::Greater => {
                panic!("Vec size greater than max size, error in GasTracker vecDeque logic")
            }
        }
    }

    /// Gets the latest gas price and adds it to the array if this fails
    /// the sample is skipped, returns a gas price if one is successfully added
    pub async fn sample_and_update(&mut self, web30: &Web3) -> Option<Uint256> {
        let sample = GasTracker::sample(web30).await;
        match sample {
            Some(entry) => {
                self.update(entry.clone());
                Some(entry.sample)
            }
            None => {
                warn!("Failed to update gas price sample");
                None
            }
        }
    }

    /// Look through all the gas prices in the history range and determine the highest
    /// acceptable price to pay as provided by a user percentage
    pub fn get_acceptable_gas_price(&self, percentage: f32) -> Option<Uint256> {
        // if there are no entries, return that no gas price should currently
        // be taken
        if self.history.is_empty() {
            return None;
        }

        let mut vector: Vec<&GasPriceEntry> = Vec::from_iter(self.history.iter());
        vector.sort();
        // this should never panic as percentage is less than 1 and vector len is
        // included as a factor
        let lowest: usize = (percentage * vector.len() as f32).floor() as usize;
        Some(vector[lowest].sample)
    }
}

/// Tests actual gas price storage by simultaneously requesting gas price and updating the GasTracker
#[test]
fn test_gas_storage() {
    use actix::System;
    use futures::future::join;
    use std::time::Duration;

    let runner = System::new();
    let web3 = Web3::new("https://eth.althea.net", Duration::from_secs(5));

    runner.block_on(async move {
        let mut tracker = GasTracker::new(10);

        let gas_fut = web3.eth_gas_price();
        let track_fut = tracker.sample_and_update(&web3);
        let (gas, track) = join(gas_fut, track_fut).await;
        let gas = gas.expect("Actix failure");

        assert!(
            track.is_some() && gas == track.unwrap(),
            "bad gas price stored - actual {gas} != stored {track:?}"
        );
    });
}

/// Checks that the acceptable gas prices are as expected with prices in the range of 0-99
#[test]
fn test_acceptable_gas_price() {
    use std::time::Instant;
    // use env_logger::{Builder, Env};
    // Builder::from_env(Env::default().default_filter_or("info")).init(); // Change log level

    // the numbers 0-99 in no particular order
    let history_values: Vec<u8> = vec![
        33, 67, 22, 57, 78, 1, 56, 49, 81, 18, 17, 7, 50, 99, 84, 89, 13, 59, 14, 27, 75, 24, 82,
        63, 31, 2, 4, 41, 79, 92, 45, 20, 30, 34, 25, 64, 21, 0, 86, 46, 32, 19, 11, 51, 71, 70,
        62, 29, 35, 88, 94, 77, 43, 9, 65, 44, 69, 8, 90, 16, 58, 97, 87, 83, 15, 12, 61, 60, 48,
        37, 73, 53, 74, 95, 98, 96, 23, 93, 91, 10, 40, 66, 42, 5, 36, 55, 54, 72, 47, 39, 28, 85,
        6, 3, 76, 38, 80, 68, 52, 26,
    ];

    // Create a gas tracker with the above values and unimportant sample_times
    let history = history_values.iter().map(|v| GasPriceEntry {
        sample: (*v).into(),
        sample_time: Instant::now(),
    });
    let tracker = GasTracker {
        history: VecDeque::from_iter(history),
        size: 100,
    };

    // All the values directly align to percentage values, so we ensure the gas tracker returns
    // x +- 1 when requesting the lowest x% price
    for i in history_values {
        if i == 0 {
            // expected_low panics on i = 0
            continue;
        }
        let expect = f32::from(i).floor();
        let percent = expect / 100.0;

        let expected_high = Uint256::from((expect as u32) + 1u32);
        let expected_low = Uint256::from((expect as u32) - 1u32);
        let acceptable = tracker.get_acceptable_gas_price(percent);
        assert!(
            acceptable.is_some(),
            "got None from get_acceptable_gas_price with nonempty history"
        );
        let acceptable = acceptable.unwrap();
        assert!(
            acceptable <= expected_high && acceptable >= expected_low,
            "percentage {percent:.8} expected range [{expected_low:?} <= {acceptable:?} <= {expected_high:?}]",
        )
    }
}
