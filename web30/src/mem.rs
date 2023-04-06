//! This module contains an extremely simple memory usage parser for Linux based systems.
//! Obviously this will not work on other platforms and we'll default to our normal buffer size.
//! The intent is to protect low memory systems (usually embedded Linux) from crashes caused by
//! OOM events. This may not work in containers or on specific cloud systems either.

use std::cmp::min;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;

/// This struct represents memory info in a Linux
/// system parsed from 'proc/meminfo'. All amounts
/// are in kilobytes
#[derive(Copy, Clone, PartialEq, Eq)]
struct MemInfo {
    /// total system memory
    mem_total: usize,
    /// memory not currently used by anything
    mem_free: usize,
    /// memory not used + memory used by disk cache
    mem_available: usize,
}

fn get_memory_info() -> Option<MemInfo> {
    let lines = get_lines("/proc/meminfo")?;
    let mut lines = lines.iter();
    let mem_total: usize = match lines.next() {
        Some(line) => match line.split_whitespace().nth(1) {
            Some(val) => {
                let res = val.parse();
                if res.is_err() {
                    return None;
                }
                res.unwrap()
            }
            None => return None,
        },
        None => return None,
    };
    let mem_free: usize = match lines.next() {
        Some(line) => match line.split_whitespace().nth(1) {
            Some(val) => {
                let res = val.parse();
                if res.is_err() {
                    return None;
                }
                res.unwrap()
            }
            None => return None,
        },
        None => return None,
    };
    let mem_available: usize = match lines.next() {
        Some(line) => match line.split_whitespace().nth(1) {
            Some(val) => {
                let res = val.parse();
                if res.is_err() {
                    return None;
                }
                res.unwrap()
            }
            None => return None,
        },
        None => return None,
    };

    Some(MemInfo {
        mem_available,
        mem_free,
        mem_total,
    })
}

fn get_lines(filename: &str) -> Option<Vec<String>> {
    let f = File::open(filename);

    if f.is_err() {
        return None;
    }
    let f = f.unwrap();

    let file = BufReader::new(&f);
    let mut out_lines = Vec::new();
    for line in file.lines() {
        match line {
            Ok(val) => out_lines.push(val),
            Err(_) => break,
        }
    }

    Some(out_lines)
}

/// Gets the request buffer size which is either DEFAULT_BUFFER or the systems
/// available memory if parsing /proc/meminfo succeeds, the DEFAULT_BUFFER size
/// is larger than the total memory available on many users systems, this is ok
/// must of the time because the memory is not actually allocated until it is used.
///
/// On the other hand it is possible for a payload that large to be sent, and the
/// program or worse the system, will die due out of memory. This function resolves this
/// issue for a subset of users running Linux by using the systems available memory, for
/// those users an OOM crash will be impossible no matter the input size, although parsing
/// will of course fail in that case.
pub fn get_buffer_size() -> usize {
    // default buffer size of 10GB in bytes, this is excessive by a good margin
    // but memory is not actually allocated until it is used
    const DEFAULT_BUFFER: usize = usize::MAX;
    if let Some(mem_status) = get_memory_info() {
        trace!("Successfully got memory info",);
        // proc/meminfo has memory in kilobytes but the buffer uses bytes for it's memory
        // size spec, we perform a conversion here. The only way this can ever fail is if
        // we have a very strange system where memory addressing has several more bits than
        // the system integer size and then that system is actually loaded with a huge amount
        // of memory.
        let mul_res = mem_status.mem_available.checked_mul(1000);
        match mul_res {
            Some(value) => {
                // effectively just checking for zero, since this is probably
                // a parsing error we're going to ignore it
                let div_res = value.checked_div(2);
                match div_res {
                    Some(value) => min(DEFAULT_BUFFER, value),
                    None => DEFAULT_BUFFER,
                }
            }
            None => DEFAULT_BUFFER,
        }
    } else {
        DEFAULT_BUFFER
    }
}
