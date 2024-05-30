use ark_bls12_381::{
    g1, g2, Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective,
};
use ark_ec::{
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},
    pairing::{Pairing, PairingOutput},
    short_weierstrass, AffineRepr, CurveGroup,
};
use ark_ff::field_hashers::DefaultFieldHasher;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{ops::Mul, vec::Vec};
use serde::{Deserialize, Serialize};
use serde_with::DeserializeAs;
use thiserror::Error;

use crate::{G1_DOMAIN, G1_SIZE, G2_DOMAIN, G2_SIZE};

#[derive(Error, Debug)]
pub enum SWEError {
    #[error("hash cannot be mapped to {0}")]
    HashToCurve(String),
    #[error("cannot initialise mapper for {hash} to BLS12-381 {field}")]
    MapperInitialisation { hash: String, field: String },
    #[error("sigma does not fit in 16 bytes")]
    MessageSize,
    #[error("pairing requires affines to be on different curves")]
    Pairing,
    #[error("invalid public key size")]
    PublicKeySize,
    #[error("serialization failed")]
    Serialisation,
    #[error("unknown data store error")]
    Unknown,
}

#[derive(Clone, Debug, PartialEq)]
pub enum GAffine {
    G1Affine(G1Affine),
    G2Affine(G2Affine),
}

impl Serialize for GAffine {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut bytes = vec![];
        match self {
            Self::G1Affine(g) => g
                .serialize_with_mode(&mut bytes, ark_serialize::Compress::Yes)
                .map_err(serde::ser::Error::custom)?,
            Self::G2Affine(g) => g
                .serialize_with_mode(&mut bytes, ark_serialize::Compress::Yes)
                .map_err(serde::ser::Error::custom)?,
        }

        serializer.serialize_bytes(&bytes)
    }
}

impl<'de> Deserialize<'de> for GAffine {
    fn deserialize<D>(deserializer: D) -> std::result::Result<GAffine, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde_with::Bytes::deserialize_as(deserializer)?;
        let reader = bytes.as_slice();
        let affine = match reader.len() {
            G1_SIZE => Self::G1Affine(
                G1Affine::deserialize_compressed(bytes.as_slice())
                    .map_err(serde::de::Error::custom)?,
            ),
            G2_SIZE => Self::G2Affine(
                G2Affine::deserialize_compressed(bytes.as_slice())
                    .map_err(serde::de::Error::custom)?,
            ),
            _ => return Err(serde::de::Error::custom("Invalid len Should be 48 of 96")),
        };
        Ok(affine)
    }
}

impl GAffine {
    pub fn projective_pairing(
        &self,
        id: &[u8],
    ) -> anyhow::Result<PairingOutput<ark_bls12_381::Bls12_381>> {
        match self {
            GAffine::G1Affine(g) => {
                let mapper = MapToCurveBasedHasher::<
                    short_weierstrass::Projective<g2::Config>,
                    DefaultFieldHasher<sha2::Sha256, 128>,
                    WBMap<g2::Config>,
                >::new(G2_DOMAIN)
                .map_err(|_| SWEError::MapperInitialisation {
                    hash: "sha2".to_owned(),
                    field: "G2".to_owned(),
                })?;
                let qid = G2Projective::from(
                    mapper
                        .hash(id)
                        .map_err(|_| SWEError::HashToCurve("G2".to_owned()))?,
                )
                .into_affine();
                Ok(Bls12_381::pairing(g, qid))
            }
            GAffine::G2Affine(g) => {
                let mapper = MapToCurveBasedHasher::<
                    short_weierstrass::Projective<g1::Config>,
                    DefaultFieldHasher<sha2::Sha256, 128>,
                    WBMap<g1::Config>,
                >::new(G1_DOMAIN)
                .map_err(|_| SWEError::MapperInitialisation {
                    hash: "sha2".to_owned(),
                    field: "G1".to_owned(),
                })?;
                let qid = G1Projective::from(
                    mapper
                        .hash(id)
                        .map_err(|_| SWEError::HashToCurve("G1".to_owned()))?,
                )
                .into_affine();
                Ok(Bls12_381::pairing(qid, g))
            }
        }
    }

    pub fn pairing(
        &self,
        other: &GAffine,
    ) -> anyhow::Result<PairingOutput<ark_bls12_381::Bls12_381>, SWEError> {
        match (self, other) {
            (GAffine::G1Affine(s), GAffine::G2Affine(o)) => Ok(Bls12_381::pairing(s, o)),
            (GAffine::G2Affine(s), GAffine::G1Affine(o)) => Ok(Bls12_381::pairing(o, s)),
            _ => Err(SWEError::Pairing),
        }
    }

    pub fn generator(&self) -> Self {
        match self {
            GAffine::G1Affine(_) => GAffine::G1Affine(G1Affine::generator()),
            GAffine::G2Affine(_) => GAffine::G2Affine(G2Affine::generator()),
        }
    }

    pub fn mul(&self, s: Fr) -> Self {
        match self {
            GAffine::G1Affine(g) => GAffine::G1Affine(g.mul(s).into_affine()),
            GAffine::G2Affine(g) => GAffine::G2Affine(g.mul(s).into_affine()),
        }
    }

    pub fn add(&self, other: &Self) -> Self {
        match (self, other) {
            (GAffine::G1Affine(s), GAffine::G1Affine(o)) => {
                GAffine::G1Affine((*s + *o).into_affine())
            }
            (GAffine::G2Affine(s), GAffine::G2Affine(o)) => {
                GAffine::G2Affine((*s + *o).into_affine())
            }
            _ => panic!("Invalid addition"),
        }
    }

    pub fn to_compressed(&self) -> anyhow::Result<Vec<u8>, SWEError> {
        let mut compressed = vec![];
        match self {
            GAffine::G1Affine(g) => {
                g.serialize_with_mode(&mut compressed, ark_serialize::Compress::Yes)
            }
            GAffine::G2Affine(g) => {
                g.serialize_with_mode(&mut compressed, ark_serialize::Compress::Yes)
            }
        }
        .map_err(|_| SWEError::Serialisation)?;
        Ok(compressed)
    }

    pub fn to_uncompressed(&self) -> anyhow::Result<Vec<u8>, SWEError> {
        let mut compressed = vec![];
        match self {
            GAffine::G1Affine(g) => {
                g.serialize_with_mode(&mut compressed, ark_serialize::Compress::No)
            }
            GAffine::G2Affine(g) => {
                g.serialize_with_mode(&mut compressed, ark_serialize::Compress::No)
            }
        }
        .map_err(|_| SWEError::Serialisation)?;
        Ok(compressed)
    }
}

impl TryFrom<&[u8]> for GAffine {
    type Error = SWEError;

    fn try_from(bytes: &[u8]) -> anyhow::Result<Self, Self::Error> {
        if bytes.len() == G1_SIZE {
            let g = G1Affine::deserialize_compressed(bytes).map_err(|_| SWEError::PublicKeySize)?;
            Ok(GAffine::G1Affine(g))
        } else if bytes.len() == G2_SIZE {
            let g = G2Affine::deserialize_compressed(bytes).map_err(|_| SWEError::PublicKeySize)?;
            Ok(GAffine::G2Affine(g))
        } else {
            Err(SWEError::PublicKeySize)
        }
    }
}
