use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{de::Visitor, Deserializer, Serializer};
use std::fmt;

pub fn serialize<T, S>(t: &T, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: CanonicalSerialize,
{
    let mut v = Vec::new();
    t.serialize_uncompressed(&mut v)
        .map_err(|_| serde::ser::Error::custom("ark error"))?;
    s.serialize_bytes(&v)
}

pub fn deserialize<'a, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'a>,
    T: CanonicalDeserialize,
{
    let v = d.deserialize_bytes(BV)?;
    let t = T::deserialize_uncompressed(v.as_slice())
        .map_err(|_| serde::de::Error::custom("ark Error"))?;
    Ok(t)
}

struct BV;

impl<'a> Visitor<'a> for BV {
    type Value = Vec<u8>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a byte sequence")
    }

    fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
        Ok(v.to_vec())
    }

    fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
        Ok(v)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'a>,
    {
        let mut v = Vec::new();
        loop {
            match seq.next_element() {
                Ok(Some(x)) => v.push(x),
                Ok(None) => return Ok(v),
                Err(e) => return Err(e),
            }
        }
    }
}
