// Copyright 2012 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![allow(missing_docs)]
#![allow(deprecated)] // Float

/// Extracted collection of all the summary statistics of a sample set.
#[derive(Clone, PartialEq)]
#[allow(missing_docs)]
pub struct Summary {
    pub sum: f64,
    pub mean: f64,
    pub median: f64,
    pub var: f64,
    pub std_dev: f64,
    pub median_abs_dev: f64,
    pub quartiles: (f64, f64, f64),
}
