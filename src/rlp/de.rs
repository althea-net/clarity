use crate::rlp::error::{Error, Result};
use crate::rlp::rlp::ExpectedType;
use serde::de::{self, Deserialize, DeserializeSeed, SeqAccess, Visitor};
use std::collections::VecDeque;
use std::ops::{AddAssign, MulAssign, Neg};
use std::str;

pub struct Deserializer<'de> {
    input: &'de [u8],
    /// Stacked input slices for nested data
    stack: VecDeque<&'de [u8]>,
}

impl<'de> Deserializer<'de> {
    pub fn from_bytes(input: &'de [u8]) -> Self {
        Deserializer {
            input: input,
            stack: VecDeque::new(),
        }
    }
}

pub fn from_bytes<'a, T>(s: &'a [u8]) -> Result<T>
where
    T: Deserialize<'a>,
{
    let mut deserializer = Deserializer::from_bytes(s);
    let t = T::deserialize(&mut deserializer)?;
    if deserializer.input.len() == 0 {
        Ok(t)
    } else {
        Err(Error::TrailingBytes)
    }
}

impl<'de> Deserializer<'de> {
    // Parse the JSON identifier `true` or `false`.
    fn parse_bool(&mut self) -> Result<bool> {
        unimplemented!();
    }

    fn parse_unsigned<T>(&mut self) -> Result<T>
    where
        T: AddAssign<T> + MulAssign<T> + From<u8>,
    {
        unimplemented!();
    }

    fn parse_signed<T>(&mut self) -> Result<T>
    where
        T: Neg<Output = T> + AddAssign<T> + MulAssign<T> + From<i8>,
    {
        // Optional minus sign, delegate to `parse_unsigned`, negate if negative.
        unimplemented!()
    }

    fn parse_string(&mut self) -> Result<&'de str> {
        let res = crate::rlp::rlp::decode_length(&self.input)?;
        if res.expected_type == ExpectedType::StringType {
            let s = str::from_utf8(&self.input[res.offset..res.offset + res.length])
                .map_err(|_| Error::InvalidString)?;
            self.input = &self.input[res.offset + res.length..];
            Ok(s)
        } else {
            Err(Error::ExpectedString)
        }
    }

    fn parse_bytes(&mut self) -> Result<&'de [u8]> {
        let res = crate::rlp::rlp::decode_length(&self.input)?;
        if res.expected_type == ExpectedType::StringType {
            let s = &self.input[res.offset..res.offset + res.length];
            self.input = &self.input[res.offset + res.length..];
            Ok(s)
        } else {
            Err(Error::ExpectedString)
        }
    }
}

impl<'de, 'a> de::Deserializer<'de> for &'a mut Deserializer<'de> {
    type Error = Error;

    fn deserialize_any<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!();
    }

    fn deserialize_bool<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_bool(self.parse_bool()?)
    }

    // The `parse_signed` function is generic over the integer type `T` so here
    // it is invoked with `T=i8`. The next 8 methods are similar.
    fn deserialize_i8<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_i8(self.parse_signed()?)
    }

    fn deserialize_i16<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_i16(self.parse_signed()?)
    }

    fn deserialize_i32<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_i32(self.parse_signed()?)
    }

    fn deserialize_i64<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_i64(self.parse_signed()?)
    }

    fn deserialize_u8<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_u8(self.parse_unsigned()?)
    }

    fn deserialize_u16<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_u16(self.parse_unsigned()?)
    }

    fn deserialize_u32<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_u32(self.parse_unsigned()?)
    }

    fn deserialize_u64<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_u64(self.parse_unsigned()?)
    }

    fn deserialize_f32<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }

    // Float parsing is stupidly hard.
    fn deserialize_f64<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }

    fn deserialize_char<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        // Parse a string, check that it is one character, call `visit_char`.
        unimplemented!()
    }

    // Refer to the "Understanding deserializer lifetimes" page for information
    // about the three deserialization flavors of strings in Serde.
    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_borrowed_str(self.parse_string()?)
    }

    fn deserialize_string<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_str(visitor)
    }

    // The `Serializer` implementation on the previous page serialized byte
    // arrays as JSON arrays of bytes. Handle that representation here.
    fn deserialize_bytes<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_borrowed_bytes(self.parse_bytes()?)
    }

    fn deserialize_byte_buf<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }

    fn deserialize_option<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!();
    }

    fn deserialize_unit<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!();
    }

    fn deserialize_unit_struct<V>(self, _name: &'static str, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_unit(visitor)
    }

    fn deserialize_newtype_struct<V>(self, _name: &'static str, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V>(mut self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let res = crate::rlp::rlp::decode_length(&self.input)?;
        if res.expected_type == ExpectedType::ListType {
            let nested = &self.input[res.offset..res.offset + res.length];
            self.stack.push_front(&self.input);
            self.input = nested;
            let value = visitor.visit_seq(RlpListDecoder::new(&mut self))?;
            self.input = self.stack.pop_front().unwrap();
            self.input = &self.input[res.offset + res.length..];
            Ok(value)
        } else {
            Err(Error::ExpectedList)
        }
    }

    fn deserialize_tuple<V>(self, _len: usize, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_seq(visitor)
    }

    fn deserialize_tuple_struct<V>(
        self,
        _name: &'static str,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_seq(visitor)
    }

    fn deserialize_map<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!();
    }

    fn deserialize_struct<V>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_map(visitor)
    }

    fn deserialize_enum<V>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        _visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!();
    }

    fn deserialize_identifier<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_str(visitor)
    }

    fn deserialize_ignored_any<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_any(visitor)
    }
}

// In order to handle commas correctly when deserializing a JSON array or map,
// we need to track whether we are on the first element or past the first
// element.
struct RlpListDecoder<'a, 'de: 'a> {
    de: &'a mut Deserializer<'de>,
}

impl<'a, 'de> RlpListDecoder<'a, 'de> {
    fn new(de: &'a mut Deserializer<'de>) -> Self {
        RlpListDecoder { de }
    }
}

// `SeqAccess` is provided to the `Visitor` to give it the ability to iterate
// through elements of the sequence.
impl<'de, 'a> SeqAccess<'de> for RlpListDecoder<'a, 'de> {
    type Error = Error;

    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>>
    where
        T: DeserializeSeed<'de>,
    {
        if self.de.input.len() == 0 {
            // No more elements
            return Ok(None);
        }
        match crate::rlp::rlp::decode_length(&self.de.input)?.expected_type {
            ExpectedType::StringType => {
                let result = seed.deserialize(&mut *self.de);
                result.map(Some)
            }
            ExpectedType::ListType => {
                // Here we don't consume boundaries of a list, and let the deserializer create new deserializer for this sequence.
                let result = seed.deserialize(&mut *self.de);
                result.map(Some)
            }
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

#[test]
fn deserialize_short_string() {
    let foo: String = from_bytes(&[0x61u8]).unwrap();
    assert_eq!(foo, "a");
}

#[test]
fn deserialize_longer_string() {
    let foo: String = from_bytes(&[0x83, 0x61, 0x62, 0x63]).unwrap();
    assert_eq!(foo, "abc");
}

#[test]
fn deserialize_short_array() {
    let foo: Vec<String> =
        from_bytes(&[0xc8, 0x83, 0x61, 0x62, 0x63, 0x83, 0x64, 0x65, 0x66]).unwrap();
    assert_eq!(foo, vec!["abc", "def"]);
}

#[test]
fn deserialize_short_array_into_tuple() {
    let (abc, def): (String, String) =
        from_bytes(&[0xc8, 0x83, 0x61, 0x62, 0x63, 0x83, 0x64, 0x65, 0x66]).unwrap();
    assert_eq!(abc, "abc");
    assert_eq!(def, "def");
}

#[test]
fn deserialize_nested_sequence_of_string_seq() {
    let foo: Vec<Vec<String>> =
        from_bytes(&[0xc9, 0xc8, 0x83, 0x61, 0x62, 0x63, 0x83, 0x64, 0x65, 0x66]).unwrap();
    assert_eq!(foo, vec![vec!["abc", "def"]]);
}

#[test]
fn deserialize_set_representation_of_three() {
    //
    let foo = from_bytes(&[0xc7, 0xc0, 0xc1, 0xc0, 0xc3, 0xc0, 0xc1, 0xc0]);
    assert_eq!(
        foo,
        Ok(vec![
            vec![],
            vec![vec![]],
            vec![vec![], vec![Vec::<u8>::new()]],
        ])
    );
}

#[test]
fn deserialize_three_levels() {
    let foo: Vec<Vec<Vec<String>>> = from_bytes(&[
        0xca, 0xc9, 0xc8, 0x83, 0x61, 0x62, 0x63, 0x83, 0x64, 0x65, 0x66,
    ])
    .unwrap();
    assert_eq!(foo, [[["abc", "def"]]]);
}

#[test]
#[should_panic]
fn simple_invalid() {
    let _foo: String = from_bytes(&[0x83, 0x61, 0x62, 0x63, /* excess */ 0xff]).unwrap();
}

#[cfg(test)]
fn get_bytes(b: &str) -> Option<Vec<u8>> {
    b.as_bytes()
        .chunks(2)
        .map(|ch| {
            str::from_utf8(&ch)
                .ok()
                .and_then(|res| u8::from_str_radix(&res, 16).ok())
        })
        .collect()
}

#[test]
fn invalid_complex() {
    use serde_bytes::Bytes;
    let data = get_bytes("f86103018207d094b94f5374fce5edbc8e2a8697c15331677e6ebf0b0a8255441ca098ff921201554726367d2be8c00804a7ff89ccf285ebc57dff8ae4c44b9c19ac4aa08887321be575c8095f789dd4c743dfe42c1820f9231f98a962b210e3ac2452a3").unwrap();
    let val: Result<Vec<&Bytes>> = from_bytes(&data);
    let val = val.unwrap_err();

    assert_eq!(val, Error::WrongPrefix);
}

#[test]
fn lorem_ipsum() {
    let data: String = from_bytes(&vec![
        0xb8, 0x38, 0x4c, 0x6f, 0x72, 0x65, 0x6d, 0x20, 0x69, 0x70, 0x73, 0x75, 0x6d, 0x20, 0x64,
        0x6f, 0x6c, 0x6f, 0x72, 0x20, 0x73, 0x69, 0x74, 0x20, 0x61, 0x6d, 0x65, 0x74, 0x2c, 0x20,
        0x63, 0x6f, 0x6e, 0x73, 0x65, 0x63, 0x74, 0x65, 0x74, 0x75, 0x72, 0x20, 0x61, 0x64, 0x69,
        0x70, 0x69, 0x73, 0x69, 0x63, 0x69, 0x6e, 0x67, 0x20, 0x65, 0x6c, 0x69, 0x74,
    ])
    .unwrap();
    assert_eq!(
        data,
        "Lorem ipsum dolor sit amet, consectetur adipisicing elit"
    );
}


#[test]
fn unsigned_eth_transaction() {
    use serde_bytes::Bytes;
    let data = get_bytes("f83f8085e8d4a510008227108080af6025515b525b600a37f260003556601b596020356000355760015b525b54602052f260255860005b525b54602052f2808080").unwrap();
    let decoded: Vec<&Bytes> = from_bytes(&data).unwrap();

    assert_eq!(
        decoded,
        vec![
            Bytes::new(&[]),
            Bytes::new(&[232, 212, 165, 16, 0]),
            Bytes::new(&[39, 16]),
            Bytes::new(&[]),
            Bytes::new(&[]),
            Bytes::new(&[
                96, 37, 81, 91, 82, 91, 96, 10, 55, 242, 96, 0, 53, 86, 96, 27, 89, 96, 32, 53, 96,
                0, 53, 87, 96, 1, 91, 82, 91, 84, 96, 32, 82, 242, 96, 37, 88, 96, 0, 91, 82, 91,
                84, 96, 32, 82, 242,
            ]),
            Bytes::new(&[]),
            Bytes::new(&[]),
            Bytes::new(&[]),
        ]
    );
}