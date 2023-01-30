// Copyright 2018 Althea Developers
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std;
use std::fmt::{self, Display};
pub type Result<T> = std::result::Result<T, Error>;
use serde::{de, ser};

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    Message(String),
    TrailingBytes,
    EmptyBuffer,
    ListPrefixTooSmall,
    StringPrefixTooSmall,
    ExpectedList,
    ExpectedString,
    InvalidString,
    WrongPrefix,
}

impl ser::Error for Error {
    fn custom<T: Display>(msg: T) -> Self {
        Error::Message(msg.to_string())
    }
}

impl de::Error for Error {
    fn custom<T: Display>(msg: T) -> Self {
        Error::Message(msg.to_string())
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Error::Message(ref msg) => write!(f, "{msg}"),
            Error::TrailingBytes => write!(f, "Trailing bytes found at the end of input"),
            Error::EmptyBuffer => write!(f, "Empty buffer detected"),
            Error::ListPrefixTooSmall => write!(f, "List prefix is bigger than the data"),
            Error::StringPrefixTooSmall => write!(f, "String prefix is bigger than the data"),
            Error::ExpectedList => write!(f, "Expected list data"),
            Error::ExpectedString => write!(f, "Expected string"),
            Error::InvalidString => write!(f, "Unable to decode valid string"),
            Error::WrongPrefix => write!(f, "Wrong prefix"),
        }
    }
}

impl std::error::Error for Error {}
