use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use nexus_api::prover::types::*;

use crate::Result;

pub type Trace = nexus_vm::trace::Trace<nexus_vm::memory::path::Path>;

#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize)]
pub enum NexusMsg {
    Connect(String),
    Reconnect(SocketAddr),
    Connected, // TODO should send Public Params?
    Ready,

    #[serde(with = "scalars")]
    MSMReq(Vec<F1>),

    #[serde(with = "ark")]
    MSMRes(P1),

    #[serde(with = "ark")]
    LeafReq(Trace),

    #[serde(with = "ark")]
    NodeReq(Vec<(PCDNode, Trace)>),

    #[serde(with = "ark")]
    PCDRes(PCDNode),
}
pub use NexusMsg::*;

mod scalars {
    use ark_ff::{BigInt, Fp256, MontBackend, MontConfig, PrimeField};
    use serde::{de::Visitor, ser::SerializeSeq, Deserializer, Serializer};
    use std::fmt;

    type F<C> = Fp256<MontBackend<C, 4>>;
    type T<C> = Vec<F<C>>;

    pub fn serialize<C, S>(v: &T<C>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        C: MontConfig<4>,
    {
        let mut seq = s.serialize_seq(Some(v.len() * 4))?;
        for f in v.iter() {
            let BigInt([a, b, c, d]) = f.into_bigint();
            seq.serialize_element(&a)?;
            seq.serialize_element(&b)?;
            seq.serialize_element(&c)?;
            seq.serialize_element(&d)?;
        }
        seq.end()
    }

    pub fn deserialize<'a, D, C>(d: D) -> Result<T<C>, D::Error>
    where
        D: Deserializer<'a>,
        C: MontConfig<4>,
    {
        let v: Vec<u64> = d.deserialize_seq(Scalar)?;
        let mut fs = Vec::new();
        for l in v.chunks(4) {
            match F::<C>::from_bigint(BigInt([l[0], l[1], l[2], l[3]])) {
                Some(f) => fs.push(f),
                None => return Err(serde::de::Error::custom("bigint conversion")),
            }
        }
        Ok(fs)
    }

    struct Scalar;

    impl<'a> Visitor<'a> for Scalar {
        type Value = Vec<u64>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a u64 sequence")
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
}

mod ark {
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
}

pub fn encode(msg: &NexusMsg) -> Result<Vec<u8>> {
    Ok(postcard::to_stdvec(msg)?)
}

pub fn decode(v: &[u8]) -> Result<NexusMsg> {
    Ok(postcard::from_bytes(v)?)
}

pub fn encode_lz4(msg: &NexusMsg) -> Result<Vec<u8>> {
    let mut v = Vec::new();
    let lz = lz4::EncoderBuilder::new().build(&mut v)?;
    let lz = postcard::to_io(msg, lz)?;
    match lz.finish() {
        (v, Ok(())) => Ok(v.to_vec()),
        (_, Err(e)) => Err(e.into()),
    }
}

pub fn decode_lz4(v: &[u8]) -> Result<NexusMsg> {
    let mut d = lz4::Decoder::new(v)?;
    let mut v = Vec::new();
    std::io::copy(&mut d, &mut v).unwrap();
    decode(&v)
}

#[cfg(test)]
mod test {
    use super::*;

    use ark_ff::fields::AdditiveGroup;
    use nexus_prover::circuit::nop_circuit;
    use nexus_prover::pp::gen_pp;

    fn round_trip(msg: &NexusMsg) {
        let v = encode_lz4(msg).unwrap();
        let _ = decode_lz4(&v).unwrap();
    }

    #[test]
    fn round_trip_other() {
        round_trip(&Connect("ID".to_string()));
    }

    #[test]
    fn round_trip_msm() {
        round_trip(&MSMReq(vec![F1::from(33)]));
        round_trip(&MSMRes(P1::ZERO));
    }

    #[test]
    fn round_trip_leaf() {
        let t = nop_circuit(3).unwrap().0;
        round_trip(&LeafReq(t));
    }

    #[test]
    #[ignore]
    fn round_trip_node() {
        let circuit = nop_circuit(3).unwrap();
        let pp: ParPP = gen_pp(&circuit, &()).unwrap();
        let n0 = PCDNode::prove_leaf(&pp, &circuit, 0, &circuit.input(0).unwrap()).unwrap();
        let n2 = PCDNode::prove_leaf(&pp, &circuit, 2, &circuit.input(2).unwrap()).unwrap();
        let n = PCDNode::prove_parent(&pp, &circuit, &n0, &n2).unwrap();

        let i = std::time::Instant::now();
        round_trip(&NodeReq(vec![(n0, circuit.0.clone())]));
        println!("leaf ser/de {:?}", i.elapsed());

        let i = std::time::Instant::now();
        round_trip(&NodeReq(vec![(n, circuit.0)]));
        println!("node ser/de {:?}", i.elapsed());
    }
}
