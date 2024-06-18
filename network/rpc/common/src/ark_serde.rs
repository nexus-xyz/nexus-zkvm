use std::ops::Deref;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Wrapped (arkworks) type that can be serialized/deserialized with `serde`.
// TODO: serde should be derived on all workspace-types.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ArkWrapper<T>(pub T);

/// Encodes output of [`CanonicalSerialize::serialize_compressed`] into a hex string.
impl<T> Serialize for ArkWrapper<T>
where
    T: CanonicalSerialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = vec![];
        self.0
            .serialize_compressed(&mut bytes)
            .map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&hex::encode(bytes))
    }
}

impl<'de, T> Deserialize<'de> for ArkWrapper<T>
where
    T: CanonicalDeserialize,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;

        let data = T::deserialize_compressed(bytes.as_slice()).map_err(serde::de::Error::custom)?;
        Ok(Self(data))
    }
}

impl<T> From<T> for ArkWrapper<T> {
    fn from(data: T) -> Self {
        Self(data)
    }
}

impl<T> Deref for ArkWrapper<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_test_curves::{
        bls12_381::{g1::Config, Fr, FrConfig, G1Affine},
        short_weierstrass::SWCurveConfig,
        MontConfig, PrimeField,
    };

    #[test]
    fn test_serde() {
        let point = Config::GENERATOR;
        let f1 = FrConfig::MODULUS;

        let data = ArkWrapper((point, f1));
        let s = serde_json::to_string(&data).unwrap();
        assert_eq!(
            s,
            r#""bbc622db0af03afbef1a7af93fe8556c58ac1b173f3a4ea105b974974f8c68c30faca94f8c63952694d79731a7d3f11701000000fffffffffe5bfeff02a4bd5305d8a10908d83933487d9d2953a7ed73""#,
        );

        let de: ArkWrapper<(G1Affine, <Fr as PrimeField>::BigInt)> =
            serde_json::from_str(&s).unwrap();
        assert_eq!(de, data);
    }
}
