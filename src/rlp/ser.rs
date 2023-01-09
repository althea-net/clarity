// Copyright 2018 Althea Developers
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::rlp::error::{Error, Result};
use serde::ser::{self, Serialize};
use std::collections::VecDeque;
use std::marker::Sized;
use crate::rlp::rlp;

pub struct Serializer {
    // This is a vector of bytes that starts empty and bytes of RLP is appended as
    // values are serialized.
    output: Vec<u8>,
    // When going deeper into the structure (i.e. when processing vector of vectors)
    // this buffer is used to keep track of state "before" going deeper.
    // This way we can save the state, and serialize nested sequence alone, and then
    // once we're done with that sequence, we can go back to the saved state.
    buffer: VecDeque<Vec<u8>>,
}

// By convention, the public API of a Serde deserializer is one or more `to_abc`
// functions such as `to_string`, `to_bytes`, or `to_writer` depending on what
// Rust types the serializer is able to produce as output.
//
// This basic serializer supports only `to_bytes`.
pub fn to_bytes<T>(value: &T) -> Result<Vec<u8>>
where
    T: Serialize,
{
    let mut serializer = Serializer {
        output: Vec::new(),
        buffer: VecDeque::new(),
    };
    value.serialize(&mut serializer)?;
    Ok(serializer.output)
}

impl<'a> ser::Serializer for &'a mut Serializer {
    type Ok = ();
    type Error = Error;

    // Associated types for keeping track of additional state while serializing
    // compound data structures like sequences and maps. In this case no
    // additional state is required beyond what is already stored in the
    // Serializer struct.
    type SerializeSeq = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = Self;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;

    fn serialize_bool(self, _v: bool) -> Result<()> {
        unimplemented!();
    }

    // JSON does not distinguish between different sizes of integers, so all
    // signed integers will be serialized the same and all unsigned integers
    // will be serialized the same. Other formats, especially compact binary
    // formats, may need independent logic for the different sizes.
    fn serialize_i8(self, v: i8) -> Result<()> {
        self.serialize_i64(i64::from(v))
    }

    fn serialize_i16(self, v: i16) -> Result<()> {
        self.serialize_i64(i64::from(v))
    }

    fn serialize_i32(self, v: i32) -> Result<()> {
        self.serialize_i64(i64::from(v))
    }

    // Not particularly efficient but this is example code anyway. A more
    // performant approach would be to use the `itoa` crate.
    fn serialize_i64(self, _v: i64) -> Result<()> {
        unimplemented!();
    }

    fn serialize_u8(self, v: u8) -> Result<()> {
        self.serialize_bytes(&rlp::encode_number(v))
    }

    fn serialize_u16(self, v: u16) -> Result<()> {
        self.serialize_bytes(&rlp::encode_number(v))
    }

    fn serialize_u32(self, v: u32) -> Result<()> {
        self.serialize_bytes(&rlp::encode_number(v))
    }

    fn serialize_u64(self, v: u64) -> Result<()> {
        self.serialize_bytes(&rlp::encode_number(v))
    }

    fn serialize_f32(self, _v: f32) -> Result<()> {
        unimplemented!();
    }

    fn serialize_f64(self, _v: f64) -> Result<()> {
        unimplemented!();
    }

    fn serialize_char(self, v: char) -> Result<()> {
        self.serialize_str(&v.to_string())
    }

    fn serialize_str(self, v: &str) -> Result<()> {
        if v.len() == 1 && v.as_bytes()[0] < 0x80 {
            self.output.extend(v.as_bytes());
        } else {
            self.output.extend(rlp::encode_length(v.len() as u64, 0x80));
            self.output.extend(v.as_bytes());
        }
        Ok(())
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<()> {
        // TODO: There is some duplication here that could be resolved later
        if v.len() == 1 && v[0] < 0x80 {
            self.output.extend(v);
        } else {
            self.output.extend(rlp::encode_length(v.len() as u64, 0x80));
            self.output.extend(v);
        }
        Ok(())
    }

    // An absent optional is represented as the JSON `null`.
    fn serialize_none(self) -> Result<()> {
        unimplemented!();
    }

    fn serialize_some<T>(self, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        // TODO: This probably can't be done better without introducing our own convention as described in RLP specification.
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<()> {
        // TODO: How to serialize unit types?
        unimplemented!();
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<()> {
        unimplemented!();
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
    ) -> Result<()> {
        self.serialize_str(variant)
    }

    fn serialize_newtype_struct<T>(self, _name: &'static str, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(self)
    }

    fn serialize_newtype_variant<T>(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        variant.serialize(&mut *self)?;
        value.serialize(&mut *self)?;
        Ok(())
    }

    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq> {
        // Before going deeper we have to introduce state to our serializer.
        // This way we can capture output from a processed sequence.
        // Once thats done, we can pop current state at the end of the sequence.
        // We don't really care about the passed length as length is mostly unused,
        // as sequences are converted to bytes first, and then the length is
        // length of actual bytes of data.
        self.buffer.push_front(self.output.clone());
        self.output.clear();
        Ok(self)
    }

    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple> {
        // This works the same as normal sequence. Len is not used, but thats what
        // trait needs.
        self.serialize_seq(Some(len))
    }

    // Tuple structs look just like sequences in JSON.
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct> {
        // Tuple structs works the same as normal tuple (and thus like a normal sequence)
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant> {
        variant.serialize(&mut *self)?;
        Ok(self)
    }

    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap> {
        // Same as for sequences - we need to save current state of output,
        // to be able to capture serialized values.
        self.buffer.push_front(self.output.clone());
        self.output.clear();
        Ok(self)
    }

    fn serialize_struct(self, _name: &'static str, len: usize) -> Result<Self::SerializeStruct> {
        self.serialize_map(Some(len))
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant> {
        variant.serialize(&mut *self)?;
        Ok(self)
    }
}

impl<'a> ser::SerializeSeq for &'a mut Serializer {
    type Ok = ();
    type Error = Error;

    fn serialize_element<T>(&mut self, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        // Serialize element of a sequence just fine
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        // Calculate the serialization of the sequence based on the captured output.
        // Note that this output is cleared out before returning SerializeSeq instance,
        // and saved on a deque.
        let mut prefix = rlp::encode_length(self.output.len() as u64, 0xc0);
        prefix.extend(self.output.clone());
        // This will get the current output, and after that pop the top of the buffer,
        // which is the output *before* serializing the sequence.
        self.output = self.buffer.pop_front().unwrap(); // This unwrap is safe assuming the normal path of the code.
        self.output.extend(prefix);
        Ok(())
    }
}

// Same thing but for tuples.
impl<'a> ser::SerializeTuple for &'a mut Serializer {
    type Ok = ();
    type Error = Error;

    fn serialize_element<T>(&mut self, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        let mut prefix = rlp::encode_length(self.output.len() as u64, 0xc0);
        prefix.extend(self.output.clone());
        // Restore original state after capturing this sequence
        self.output = self.buffer.pop_front().unwrap();
        self.output.extend(prefix);
        Ok(())
    }
}

// Same thing but for tuple structs.
impl<'a> ser::SerializeTupleStruct for &'a mut Serializer {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        Ok(())
    }
}

impl<'a> ser::SerializeTupleVariant for &'a mut Serializer {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        Ok(())
    }
}

impl<'a> ser::SerializeMap for &'a mut Serializer {
    type Ok = ();
    type Error = Error;

    fn serialize_key<T>(&mut self, key: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        key.serialize(&mut **self)
    }

    fn serialize_value<T>(&mut self, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        Ok(())
    }
}

impl<'a> ser::SerializeStruct for &'a mut Serializer {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, key: &'static str, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        // Serialize element of a structure as a sequence [key, value].
        let dummy_seq = (&key, &value);
        dummy_seq.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        let mut prefix = rlp::encode_length(self.output.len() as u64, 0xc0);
        prefix.extend(self.output.clone());
        self.output = self.buffer.pop_front().unwrap(); // This unwrap is safe assuming the normal path of the code.
        self.output.extend(prefix);
        Ok(())
    }
}

impl<'a> ser::SerializeStructVariant for &'a mut Serializer {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, key: &'static str, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        key.serialize(&mut **self)?;
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        Ok(())
    }
}

#[test]
fn test_emptystring() {
    assert_eq!(to_bytes(&"".to_string()).unwrap(), [0x80]);
}

#[test]
fn test_shortstring() {
    assert_eq!(
        to_bytes(&"dog".to_string()).unwrap(),
        [0x83, 0x64, 0x6f, 0x67]
    );
}

#[test]
fn test_shortlist() {
    assert_eq!(
        to_bytes(&vec!["cat", "dog"]).unwrap(),
        [0xc8, 0x83, 0x63, 0x61, 0x74, 0x83, 0x64, 0x6f, 0x67]
    );
}

#[test]
fn test_shortlist_as_tuple() {
    let data = ("cat", "dog");
    assert_eq!(
        to_bytes(&data).unwrap(),
        [0xc8, 0x83, 0x63, 0x61, 0x74, 0x83, 0x64, 0x6f, 0x67]
    );
}

#[test]
fn test_wrapped_shortlist() {
    assert_eq!(
        to_bytes(&vec![vec!["cat", "dog"]]).unwrap(),
        [0xc9, 0xc8, 0x83, 0x63, 0x61, 0x74, 0x83, 0x64, 0x6f, 0x67]
    );
}

#[test]
fn test_nested_shortlist() {
    assert_eq!(
        to_bytes(&vec![vec!["cat", "dog"], vec!["cat", "dog"]]).unwrap(),
        [
            0xd2, 0xc8, 0x83, 0x63, 0x61, 0x74, 0x83, 0x64, 0x6f, 0x67, 0xc8, 0x83, 0x63, 0x61,
            0x74, 0x83, 0x64, 0x6f, 0x67,
        ]
    );
}

#[test]
fn test_long_string() {
    assert_eq!(
        to_bytes(&"Lorem ipsum dolor sit amet, consectetur adipisicing elit".to_string()).unwrap(),
        vec![
            0xb8, 0x38, 0x4c, 0x6f, 0x72, 0x65, 0x6d, 0x20, 0x69, 0x70, 0x73, 0x75, 0x6d, 0x20,
            0x64, 0x6f, 0x6c, 0x6f, 0x72, 0x20, 0x73, 0x69, 0x74, 0x20, 0x61, 0x6d, 0x65, 0x74,
            0x2c, 0x20, 0x63, 0x6f, 0x6e, 0x73, 0x65, 0x63, 0x74, 0x65, 0x74, 0x75, 0x72, 0x20,
            0x61, 0x64, 0x69, 0x70, 0x69, 0x73, 0x69, 0x63, 0x69, 0x6e, 0x67, 0x20, 0x65, 0x6c,
            0x69, 0x74,
        ]
    );
}

#[test]
fn test_integer_0() {
    assert_eq!(to_bytes(&0u8).unwrap(), vec![0x00]);
}

#[test]
fn test_integer_15() {
    assert_eq!(to_bytes(&15u8).unwrap(), vec![0x0f]);
}

#[test]
fn test_integer_1024() {
    assert_eq!(to_bytes(&1024u16).unwrap(), vec![0x82, 0x04, 0x00]);
}

#[test]
fn test_integer_1024_u32() {
    assert_eq!(to_bytes(&1024u32).unwrap(), vec![0x82, 0x04, 0x00]);
}

#[test]
fn test_array() {
    // "The set theoretical representation of three"
    let data = vec![vec![], vec![vec![]], vec![vec![], vec![Vec::<u8>::new()]]];
    assert_eq!(
        to_bytes(&data).unwrap(),
        [0xc7, 0xc0, 0xc1, 0xc0, 0xc3, 0xc0, 0xc1, 0xc0]
    );
}

#[test]
fn test_kv() {
    let data = vec![vec!["key1", "value1"], vec!["key2", "value2"]];
    assert_eq!(
        to_bytes(&data).unwrap(),
        [
            0xda, 0xcc, 0x84, 0x6b, 0x65, 0x79, 0x31, 0x86, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x31,
            0xcc, 0x84, 0x6b, 0x65, 0x79, 0x32, 0x86, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x32
        ]
    );
}
