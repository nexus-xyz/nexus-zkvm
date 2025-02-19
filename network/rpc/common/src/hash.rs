use std::fmt;

use serde::{Deserialize, Serialize};
use sha3::{
    digest::{typenum::ToInt, OutputSizeUser},
    Digest, Sha3_256, Sha3_256Core,
};

/// zkVM version set by the workspace, in a semver format, e.g. "1.0.0"
///
/// Prefixes the program bytes when computing hash.
pub const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

type HashBytes = [u8; <Sha3_256Core as OutputSizeUser>::OutputSize::USIZE];
/// Hash type.
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hash(#[serde(with = "hex::serde")] pub HashBytes);

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl ark_std::rand::distributions::Distribution<Hash> for ark_std::rand::distributions::Standard {
    #[inline]
    fn sample<R: ark_std::rand::Rng + ?Sized>(&self, rng: &mut R) -> Hash {
        let bytes =
            <Self as ark_std::rand::distributions::Distribution<HashBytes>>::sample(self, rng);
        Hash(bytes)
    }
}

/// Computes hash of the input bytes prefixed by the Nexus version.
pub fn hash(bytes: &[u8]) -> Hash {
    let mut hasher = Sha3_256::new();

    hasher.update(PKG_VERSION.as_bytes());
    // input should also be included, skipped for now
    hasher.update(bytes);

    Hash(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::{Digest, Sha3_256};

    #[test]
    fn test_serde() {
        // https://www.di-mgt.com.au/sha_testvectors.html

        let mut hasher = Sha3_256::new();
        hasher.update("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        let result = hasher.finalize();

        let hash = Hash(result.into());

        let ser = serde_json::to_string(&hash).unwrap();
        assert_eq!(
            ser,
            r#""41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376""#
        );

        let de: Hash = serde_json::de::from_str(&ser).unwrap();
        assert_eq!(hash, de);
    }
}
