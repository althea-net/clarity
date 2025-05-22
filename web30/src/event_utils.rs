//! This module contains functions for managing Ethereum events
use crate::{client::Web3, types::NewFilter};
use crate::{jsonrpc::error::Web3Error, types::Log};
use clarity::{
    abi::{derive_signature, AbiToken, SerializedToken},
    utils::bytes_to_hex_str,
};
use clarity::{Address, Uint256};
use std::time::{Duration, Instant};
use std::vec;
use tokio::time::sleep as delay_for;

/// Converts anything that implements Into<AbiToken> to a [u8; 32] for use in event topics
/// this then needs to be converted to a hex string with 0x prepended.
pub fn convert_to_event(value: impl Into<AbiToken>) -> [u8; 32] {
    let token = value.into();
    match token.serialize() {
        SerializedToken::Dynamic(_) => panic!("dyanmic types not supported!"),
        SerializedToken::Static(v) => v,
    }
}

/// Converts anything that implements Into<AbiToken> to a hex string with 0x prepended
/// useful as a direct argument to the topics field of a events filter
pub fn convert_to_event_string(value: impl Into<AbiToken>) -> String {
    let token = value.into();
    match token.serialize() {
        SerializedToken::Dynamic(_) => panic!("dyanmic types not supported!"),
        SerializedToken::Static(v) => bytes_to_data(&v),
    }
}

// Internal function to convert a [u8; 32] to a hex string with 0x appended
pub fn bytes_to_data(s: &[u8]) -> String {
    let mut val = "0x".to_string();
    val.push_str(&bytes_to_hex_str(s));
    val
}

/// helper: transpose a Vec of filters into per-topic buckets  
fn build_final_topics(events: &[Vec<&str>]) -> Vec<Option<Vec<Option<String>>>> {
    let max_len = events.iter().map(|f| f.len()).max().unwrap_or(0);
    let mut final_topics = Vec::with_capacity(max_len);
    for idx in 0..max_len {
        let mut column = Vec::with_capacity(events.len());
        for filter in events {
            let v = filter.get(idx).copied();
            if let Some(v) = v {
                if let Ok(sig) = derive_signature(v) {
                    column.push(Some(bytes_to_data(&sig)));
                } else if v.is_empty() {
                    column.push(None);
                } else {
                    column.push(Some(v.to_string()));
                }
            }
        }
        final_topics.push(Some(column));
    }
    final_topics
}

impl Web3 {
    /// Waits for a single event but instead of creating a filter and checking
    /// for changes this function waits for the provided wait time before
    /// checking if the event has occurred. This function will wait for at
    // least 'wait_time' before progressing, regardless of the outcome.
    pub async fn wait_for_event_alt<F: Fn(Log) -> bool + 'static>(
        &self,
        wait_time: Duration,
        contract_address: Vec<Address>,
        event: &str,
        topics: Vec<Vec<[u8; 32]>>,
        local_filter: F,
    ) -> Result<Log, Web3Error> {
        let sig = derive_signature(event)?;
        let mut final_topics = vec![Some(vec![Some(bytes_to_data(&sig))])];
        for topic in topics {
            let mut parts = Vec::new();
            for item in topic {
                parts.push(Some(bytes_to_data(&item)))
            }
            final_topics.push(Some(parts));
        }

        let new_filter = NewFilter {
            address: contract_address,
            from_block: None,
            to_block: None,
            topics: Some(final_topics),
        };

        delay_for(wait_time).await;
        let logs = match self.eth_get_logs(new_filter.clone()).await {
            Ok(logs) => logs,
            Err(e) => return Err(e),
        };

        for log in logs {
            if local_filter(log.clone()) {
                return Ok(log);
            }
        }
        Err(Web3Error::EventNotFound(event.to_string()))
    }

    /// Sets up an event filter, waits for a single event to happen, then removes the filter. Includes a
    /// local filter. If a captured event does not pass this filter, it is ignored. This differs from
    /// wait_for_event_alt in that it will check for filter changes every second and potentially exit
    /// earlier than the wait_for time provided by the user.
    pub async fn wait_for_event<F: Fn(Log) -> bool + 'static>(
        &self,
        wait_for: Duration,
        contract_address: Vec<Address>,
        event: &str,
        topics: Vec<Vec<[u8; 32]>>,
        local_filter: F,
    ) -> Result<Log, Web3Error> {
        let sig = derive_signature(event)?;
        let mut final_topics = vec![Some(vec![Some(bytes_to_data(&sig))])];
        for topic in topics {
            let mut parts = Vec::new();
            for item in topic {
                parts.push(Some(bytes_to_data(&item)))
            }
            final_topics.push(Some(parts));
        }

        let new_filter = NewFilter {
            address: contract_address,
            from_block: None,
            to_block: None,
            topics: Some(final_topics),
        };

        let filter_id = match self.eth_new_filter(new_filter).await {
            Ok(f) => f,
            Err(e) => return Err(e),
        };

        let start = Instant::now();
        let mut found_log = None;
        while Instant::now() - start < wait_for {
            delay_for(Duration::from_secs(1)).await;
            let logs = match self.eth_get_filter_changes(filter_id).await {
                Ok(changes) => changes,
                Err(e) => return Err(e),
            };
            for log in logs {
                if local_filter(log.clone()) {
                    found_log = Some(log);
                    break;
                }
            }
        }

        if let Err(e) = self.eth_uninstall_filter(filter_id).await {
            return Err(Web3Error::CouldNotRemoveFilter(format!("{e}")));
        }

        match found_log {
            Some(log) => Ok(log),
            None => Err(Web3Error::EventNotFound(event.to_string())),
        }
    }

    /// Checks for multiple events each with additonal topics, the first argument of each vec of strings should be an event signature
    /// followed by topics, topics are positional, so if you want to skip a topic provide an empty string. If no ending block is provided
    /// the latest will be used. This function will not wait for events to occur.  
    /// An empty vec on the topics filter will return all events from the target contract.
    /// Formatting limitations for queries for multiple events matching on multiple topics:
    ///   Some more complex queries may not work as expected.
    ///   Lets say we have three events
    ///   - FirstEvent(indxed address, indexed uint256, indexed string, string)
    ///   - SecondEvent(indxed address, indexed uint256, string) 
    ///   - ThirdEvent(indxed address, indexed uint256, indexed string, string)
    /// 
    ///   For this filter:
    ///   - FirstEvent(0x123, 1, "A")
    ///   - ThirdEvent(0x123, 1, "A", "B")
    /// 
    ///   No results will be returned for the First event because the third topic does not have a placeholder. Events for the
    ///   Third event will be returned.
    /// 
    ///   For this filter:
    ///   - FirstEvent(0x123, 1, "A", "")
    ///   - ThirdEvent(0x123, 1, "A", "B")
    /// 
    ///   Results from both events will be returned as you might expect.
    /// 
    ///   For this filter:
    ///   - FirstEvent(0x123, 1, "A", "")
    ///   - SecondEvent(0x123, 1, "A", "")
    ///   - ThirdEvent(0x123, 1, "A", "B")
    /// 
    ///   Results from the second event will not be returned, because SecondEvent has only 2 indexed topics. Results from the First and Third
    ///   events will be returned. Leaving out the "" for Second event will not work either.
    ///
    ///   tl;dr The maximum number of indexed topics you can match when searching multiple events is the minimum number of indexed topics on any event
    ///          in the search.
    pub async fn check_for_multiple_events(
        &self,
        start_block: Uint256,
        end_block: Option<Uint256>,
        contract_address: Vec<Address>,
        events: Vec<Vec<&str>>,
    ) -> Result<Vec<Log>, Web3Error> {
        let from_block = Some(format!("{start_block:#x}"));
        let to_block = match end_block {
            Some(e) => Some(format!("{e:#x}")),
            None => Some(format!("{:#x}", self.eth_block_number().await?)),
        };

        let final_topics = build_final_topics(&events);

        let new_filter = NewFilter {
            address: contract_address,
            from_block,
            to_block,
            topics: Some(final_topics),
        };
        self.eth_get_logs(new_filter).await
    }

    /// Checks an event with additional topics, the first argumement should always be an event signature, with the following being
    /// topics, topics are positional, so if you want to skip a topic provide an empty string. If no ending block is provided
    /// the latest will be used. This function will not wait for events to occur. Note this is a simplified endpoint that does not
    /// fully represent the eth_getLogs endpoint, use eth_get_logs for the full power of event requests.
    /// An emtpy vec on the topics filter will return all events from the target contract.
    pub async fn check_for_events(
        &self,
        start_block: Uint256,
        end_block: Option<Uint256>,
        contract_address: Vec<Address>,
        events: Vec<&str>,
    ) -> Result<Vec<Log>, Web3Error> {
        // Build a filter with specified topics
        let from_block = Some(format!("{start_block:#x}"));
        let to_block;
        if let Some(end_block) = end_block {
            to_block = Some(format!("{end_block:#x}"));
        } else {
            let latest_block = self.eth_block_number().await?;
            to_block = Some(format!("{latest_block:#x}"));
        }

        let mut final_topics = Vec::new();
        for event in events {
            if let Ok(sig) = derive_signature(event) {
                final_topics.push(Some(vec![Some(bytes_to_data(&sig))]));
            } else if event.is_empty() {
                final_topics.push(None);
            } else {
                final_topics.push(Some(vec![Some(event.to_string())]));
            }
        }

        let new_filter = NewFilter {
            address: contract_address,
            from_block,
            to_block,
            topics: Some(final_topics),
        };

        self.eth_get_logs(new_filter).await
    }
}

#[cfg(test)]
mod tests {
    use super::build_final_topics;

    #[test]
    fn transpose_unequal_lengths() {
        let events = vec![vec!["123", "", "456", "789"], vec!["ABC", "DEF"]];
        let topics = build_final_topics(&events);
        println!("topics: {topics:#?}");
        assert_eq!(topics.len(), 4);

        let col0 = topics[0].as_ref().unwrap();
        assert_eq!(col0.len(), 2);
        assert!(col0[0].is_some());
        assert!(col0[1].is_some());

        let col1 = topics[1].as_ref().unwrap();
        assert_eq!(col1.len(), 2);
        assert!(col1[0].is_none());
        assert!(col1[1].is_some());

        let col2 = topics[2].as_ref().unwrap();
        assert_eq!(col2.len(), 1);
        assert!(col2[0].is_some());

        let col3 = topics[3].as_ref().unwrap();
        assert_eq!(col2.len(), 1);
        assert!(col3[0].is_some());
    }

    #[test]
    fn transpose_unequal_lengths_2() {
        let events = vec![vec!["A()", "", "456", "789"], vec!["B()", "DEF"]];
        let topics = build_final_topics(&events);
        println!("topics: {topics:#?}");
        assert_eq!(topics.len(), 4);

        let col0 = topics[0].as_ref().unwrap();
        assert_eq!(col0.len(), 2);
        assert!(
            col0[0].as_ref().unwrap()
                == "0xf446c1d0ceceeffa77e664bc78fba57853bda372d626a510062480375fa80e90"
        );
        assert!(col0[1].is_some());

        let col1 = topics[1].as_ref().unwrap();
        assert_eq!(col1.len(), 2);
        assert!(col1[0].is_none());
        assert!(col1[1].is_some());

        let col2 = topics[2].as_ref().unwrap();
        assert_eq!(col2.len(), 1);
        assert!(col2[0].is_some());

        let col3 = topics[3].as_ref().unwrap();
        assert_eq!(col2.len(), 1);
        assert!(col3[0].is_some());
    }
}
