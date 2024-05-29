use anyhow::anyhow;
use ark_bls12_381::{
    g1, g2, Bls12_381, Config, Fr as ScalarField, G1Affine, G1Projective, G2Affine, G2Projective,
};
use ark_ec::{
    bls12::Bls12,
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},
    models::short_weierstrass,
    pairing::{Pairing, PairingOutput},
    AffineRepr, CurveGroup, Group,
};
use ark_ff::{field_hashers::DefaultFieldHasher, BigInt, PrimeField, UniformRand, Zero};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, cfg_iter, vec::Vec};
use itertools::Itertools;
use rand::Rng;
use rand::{distributions::Uniform, RngCore};
use serde::{Deserialize, Serialize};
use serde_with::DeserializeAs;
use sha2::{digest::Update, Digest, Sha256};
use std::{collections::HashMap, hash::Hash, marker::PhantomData, ops::Mul};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum IBEError {
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
                .map_err(|_| IBEError::MapperInitialisation {
                    hash: "sha2".to_owned(),
                    field: "G2".to_owned(),
                })?;
                let qid = G2Projective::from(
                    mapper
                        .hash(id)
                        .map_err(|_| IBEError::HashToCurve("G2".to_owned()))?,
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
                .map_err(|_| IBEError::MapperInitialisation {
                    hash: "sha2".to_owned(),
                    field: "G1".to_owned(),
                })?;
                let qid = G1Projective::from(
                    mapper
                        .hash(id)
                        .map_err(|_| IBEError::HashToCurve("G1".to_owned()))?,
                )
                .into_affine();
                Ok(Bls12_381::pairing(qid, g))
            }
        }
    }

    pub fn pairing(
        &self,
        other: &GAffine,
    ) -> anyhow::Result<PairingOutput<ark_bls12_381::Bls12_381>, IBEError> {
        match (self, other) {
            (GAffine::G1Affine(s), GAffine::G2Affine(o)) => Ok(Bls12_381::pairing(s, o)),
            (GAffine::G2Affine(s), GAffine::G1Affine(o)) => Ok(Bls12_381::pairing(o, s)),
            _ => Err(IBEError::Pairing),
        }
    }

    pub fn generator(&self) -> Self {
        match self {
            GAffine::G1Affine(_) => GAffine::G1Affine(G1Affine::generator()),
            GAffine::G2Affine(_) => GAffine::G2Affine(G2Affine::generator()),
        }
    }

    pub fn mul(&self, s: ScalarField) -> Self {
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

    pub fn to_compressed(&self) -> anyhow::Result<Vec<u8>, IBEError> {
        let mut compressed = vec![];
        match self {
            GAffine::G1Affine(g) => {
                g.serialize_with_mode(&mut compressed, ark_serialize::Compress::Yes)
            }
            GAffine::G2Affine(g) => {
                g.serialize_with_mode(&mut compressed, ark_serialize::Compress::Yes)
            }
        }
        .map_err(|_| IBEError::Serialisation)?;
        Ok(compressed)
    }
}

impl TryFrom<&[u8]> for GAffine {
    type Error = IBEError;

    fn try_from(bytes: &[u8]) -> anyhow::Result<Self, Self::Error> {
        if bytes.len() == G1_SIZE {
            let g = G1Affine::deserialize_compressed(bytes).map_err(|_| IBEError::PublicKeySize)?;
            Ok(GAffine::G1Affine(g))
        } else if bytes.len() == G2_SIZE {
            let g = G2Affine::deserialize_compressed(bytes).map_err(|_| IBEError::PublicKeySize)?;
            Ok(GAffine::G2Affine(g))
        } else {
            Err(IBEError::PublicKeySize)
        }
    }
}

#[derive(Clone, Debug)]
pub struct Ciphertext {
    pub c0: GAffine,
    // pub c1: PairingOutput<ark_ec::bls12::Bls12<ark_bls12_381::Config>>,
    pub cis: Vec<PairingOutput<ark_ec::bls12::Bls12<ark_bls12_381::Config>>>,
}

const BLOCK_SIZE: usize = 32;
#[cfg(feature = "rfc9380")]
pub const G1_DOMAIN: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
#[cfg(not(feature = "rfc9380"))]
pub const G1_DOMAIN: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
pub const G2_DOMAIN: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

pub const G1_SIZE: usize = 48;
pub const G2_SIZE: usize = 96;

pub fn swe_enc<I: AsRef<[u8]>, M: AsRef<[u8]>>(
    vks: &[GAffine],
    id: I,
    msg: M,
    threshold: usize,
    total: usize,
) -> anyhow::Result<Ciphertext, anyhow::Error> {
    assert!(
        msg.as_ref().len() <= BLOCK_SIZE,
        "plaintext too long for the block size"
    );

    let mut rng = rand::thread_rng();
    let bytes: [u8; 32] = rng.gen();

    let r = ScalarField::from_le_bytes_mod_order(&bytes);

    let m = ScalarField::from_le_bytes_mod_order(msg.as_ref());

    let (ss, _) = shamir_ss(&mut rng, m, threshold, total).unwrap();

    // check if shamir reconstruction works
    {
        let share_ids = (1..=6).collect_vec();
        let basis = lagrange_basis_at_0_for_all::<ScalarField>(&share_ids).unwrap();

        let m_rec = cfg_into_iter!(basis)
            .zip(cfg_into_iter!(ss.iter().take(6).cloned().collect_vec()))
            .map(|(b, s)| b * s)
            .sum::<ScalarField>();

        assert_eq!(m, m_rec, "m != m_rec");
    }

    let c0 = G2Affine::generator().mul(r);
    let c0 = GAffine::G2Affine(c0.into_affine());

    let cis = vks
        .iter()
        .zip(ss)
        .map(|(vk, s_i)| {
            let h_t_vk = vk.projective_pairing(id.as_ref()).unwrap();
            let h_t_vk_r = h_t_vk.mul(r);
            let gt_si = PairingOutput::generator().mul(s_i);
            h_t_vk_r + gt_si
        })
        .collect_vec();

    Ok(Ciphertext { c0, cis })
}

// Returns gt^m (need to calc m = dlog(gt^m))
pub fn swe_dec_dlog(
    ct: &Ciphertext,
    sigmas: impl IntoIterator<Item = GAffine>,
    share_ids: &[usize],
) -> anyhow::Result<PairingOutput<ark_ec::bls12::Bls12<ark_bls12_381::Config>>, anyhow::Error> {
    let basis = lagrange_basis_at_0_for_all::<ScalarField>(share_ids).unwrap();
    let sigma_thres = sigmas.into_iter().zip_eq(basis.iter().cloned()).fold(
        GAffine::G1Affine(G1Affine::zero()),
        |acc, (sig, l)| {
            let sig_l = sig.mul(l);
            acc.add(&sig_l)
        },
    );

    let sig_c1 = sigma_thres.pairing(&ct.c0).unwrap();

    let cis_l = share_ids
        .iter()
        .zip_eq(basis)
        .fold(PairingOutput::zero(), |acc, (i, l_i)| {
            let c_i_l = ct.cis[i - 1].mul(l_i);
            acc + c_i_l
        });

    let d = cis_l - sig_c1;

    Ok(d)
}

// Returns gt^m (need to calc m = dlog(gt^m))
pub fn swe_dec(
    ct: &Ciphertext,
    sigmas: impl IntoIterator<Item = GAffine>,
    share_ids: &[usize],
    bits_babygiant: usize,
    total_bits: usize,
    dlp_map: HashMap<PairingOutput<ark_ec::bls12::Bls12<ark_bls12_381::Config>>, u64>,
) -> anyhow::Result<u64, anyhow::Error> {
    let basis = lagrange_basis_at_0_for_all::<ScalarField>(share_ids).unwrap();
    let sigma_thres = sigmas.into_iter().zip_eq(basis.iter().cloned()).fold(
        GAffine::G1Affine(G1Affine::zero()),
        |acc, (sig, l)| {
            let sig_l = sig.mul(l);
            acc.add(&sig_l)
        },
    );

    let sig_c1 = sigma_thres.pairing(&ct.c0).unwrap();

    let cis_l = share_ids
        .iter()
        .zip_eq(basis)
        .fold(PairingOutput::zero(), |acc, (i, l_i)| {
            let c_i_l = ct.cis[i - 1].mul(l_i);
            acc + c_i_l
        });

    let d = cis_l - sig_c1;

    let msg = babygiant(d, bits_babygiant, total_bits, dlp_map);

    Ok(msg)
}

fn sign<I: AsRef<[u8]>>(id: I, sk: ScalarField) -> Result<GAffine, anyhow::Error> {
    let mapper = MapToCurveBasedHasher::<
        short_weierstrass::Projective<g1::Config>,
        DefaultFieldHasher<sha2::Sha256, 128>,
        WBMap<g1::Config>,
    >::new(G1_DOMAIN)
    .map_err(|_| IBEError::MapperInitialisation {
        hash: "sha2".to_owned(),
        field: "G1".to_owned(),
    })?;
    let ht = G1Projective::from(
        mapper
            .hash(id.as_ref())
            .map_err(|_| IBEError::HashToCurve("G1".to_owned()))?,
    );

    let sigma = ht.mul(sk).into_affine();

    Ok(GAffine::G1Affine(sigma))
}

pub fn shamir_ss<R: RngCore, F: PrimeField>(
    rng: &mut R,
    secret: F,
    threshold: usize,
    total: usize,
) -> Result<(Vec<F>, DensePolynomial<F>), anyhow::Error> {
    if threshold > total {
        return Err(anyhow::anyhow!("InvalidThresholdOrTotal"));
    }
    if total < 2 {
        return Err(anyhow::anyhow!("InvalidThresholdOrTotal"));
    }
    if threshold < 1 {
        return Err(anyhow::anyhow!("InvalidThresholdOrTotal"));
    }
    let mut coeffs = Vec::with_capacity(threshold as usize);
    coeffs.append(&mut (0..threshold - 1).map(|_| F::rand(rng)).collect());
    coeffs.insert(0, secret);
    let poly = DensePolynomial::from_coefficients_vec(coeffs);
    let shares = (1..=total)
        .map(|i| poly.evaluate(&F::from(i as u64)))
        .collect::<Vec<_>>();

    Ok((shares, poly))
}

#[cfg(test)]
mod tests {
    use ark_ff::Zero;
    use ark_std::{end_timer, start_timer};

    use super::*;

    #[test]
    fn test_mcfly_simple() {
        const N: usize = 10;
        const T: usize = 5;
        let mut rng = rand::thread_rng();

        let sks = [0; N].map(|_| ScalarField::from_le_bytes_mod_order(&rng.gen::<[u8; 32]>()));
        let vks = sks.map(|sk| GAffine::G2Affine(G2Affine::generator().mul(sk).into_affine()));

        let msg = b"t";
        let id = b"88";

        let ct = swe_enc(&vks, id, msg, T, N).unwrap();

        // sign

        let share_ids = (1..=T + 1).collect_vec();
        let sigmas = share_ids.iter().map(|i| sign(id, sks[i - 1]).unwrap());

        let d = swe_dec_dlog(&ct, sigmas, &share_ids).unwrap();

        // check dlog
        let m = ScalarField::from_le_bytes_mod_order(msg.as_ref());
        let d_test = PairingOutput::generator().mul(m);

        assert_eq!(d, d_test, "dec_dlog(enc(m)) != gt^m");
    }

    #[test]
    fn test_mcfly_full() {
        const N: usize = 10;
        const T: usize = 5;
        const BITS_BG: usize = 16;
        const BITS_TOTAL: usize = 24;
        let mut rng = rand::thread_rng();

        let sks = [0; N].map(|_| ScalarField::from_le_bytes_mod_order(&rng.gen::<[u8; 32]>()));
        let vks = sks.map(|sk| GAffine::G2Affine(G2Affine::generator().mul(sk).into_affine()));

        let msg = b"t";
        let id = b"88";

        let ct = swe_enc(&vks, id, msg, T, N).unwrap();

        // sign

        let share_ids = (1..=T + 1).collect_vec();
        let sigmas = share_ids.iter().map(|i| sign(id, sks[i - 1]).unwrap());

        let timer = start_timer!(|| "babygiant pre-compute");
        let dlp_map = babygiant_precomp(BITS_BG);
        end_timer!(timer);
        let timer = start_timer!(|| "swe decrtypt");

        let m = swe_dec(&ct, sigmas, &share_ids, BITS_BG, BITS_TOTAL, dlp_map).unwrap();
        end_timer!(timer);

        assert_eq!(m, msg[0] as u64, "dec(enc(m)) != m");
    }
}

pub fn lagrange_basis_at_0_for_all<F: PrimeField>(
    x_coords: &[usize],
) -> Result<Vec<F>, anyhow::Error> {
    let x = cfg_into_iter!(x_coords)
        .map(|x| F::from(*x as u64))
        .collect::<Vec<_>>();
    // Ensure no x-coordinate can be 0 since we are evaluating basis polynomials at 0
    if cfg_iter!(x).any(|x_i| x_i.is_zero()) {
        return Err(anyhow!("XCordCantBeZero"));
    }

    // Product of all `x`, i.e. \prod_{i}(x_i}
    let product = cfg_iter!(x).product::<F>();

    let r = cfg_into_iter!(x.clone())
        .map(move |i| {
            let mut denominator = cfg_iter!(x)
                .filter(|&j| &i != j)
                .map(|&j| j - i)
                .product::<F>();
            denominator.inverse_in_place().unwrap();

            // The numerator is of the form `x_1*x_2*...x_{i-1}*x_{i+1}*x_{i+2}*..` which is a product of all
            // `x` except `x_i` and thus can be calculated as \prod_{i}(x_i} * (1 / x_i)
            let numerator = product * i.inverse().unwrap();

            denominator * numerator
        })
        .collect::<Vec<_>>();
    Ok(r)
}

pub fn babygiant_precomp(
    bits: usize,
) -> HashMap<PairingOutput<ark_ec::bls12::Bls12<ark_bls12_381::Config>>, u64> {
    let n = 1u64 << bits;

    let mut res = HashMap::new();
    let mut tmp = PairingOutput::generator();
    for i in 1..=n {
        res.insert(tmp, i);
        tmp += PairingOutput::generator();
    }
    res
}

pub fn babygiant(
    d: PairingOutput<ark_ec::bls12::Bls12<ark_bls12_381::Config>>,
    bits_babygiant: usize,
    total_bits: usize,
    dlp_map: HashMap<PairingOutput<ark_ec::bls12::Bls12<ark_bls12_381::Config>>, u64>,
) -> u64 {
    let bits_diff = total_bits - bits_babygiant;

    let n = 1u64 << bits_babygiant;

    let mut x = d;
    let tmp = PairingOutput::generator().mul_bigint(BigInt::<1>::from(n));

    let k = 1u64 << bits_diff;
    for i in 0..=k {
        if dlp_map.contains_key(&x) {
            return dlp_map.get(&x).unwrap() + i * n
        }
        x += tmp;
    }
    
    0
}
