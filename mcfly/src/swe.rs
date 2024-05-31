use crate::{common::*, G1_DOMAIN};
use anyhow::anyhow;
use ark_bls12_381::{g1, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::{
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},
    models::short_weierstrass,
    pairing::PairingOutput,
    AffineRepr, CurveGroup, Group,
};
use ark_ff::{field_hashers::DefaultFieldHasher, BigInt, PrimeField, UniformRand};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_std::{cfg_into_iter, cfg_iter, ops::Mul, vec::Vec};
use itertools::Itertools;
use rand::RngCore;
use sha2::Digest;
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct Ciphertext {
    pub id: Vec<u8>,
    pub h: GAffine,
    pub c: GAffine,
    pub c0: GAffine,
    pub cjs: Vec<GAffine>,
    pub cdashjs: Vec<PairingOutput<ark_ec::bls12::Bls12<ark_bls12_381::Config>>>,
}

pub fn encrypt<I: AsRef<[u8]>, M: AsRef<[u8]>, R: RngCore>(
    vks: &[GAffine],
    id: I,
    msg: M,
    threshold: usize,
    total: usize,
    rng: &mut R,
    block_size: usize,
) -> anyhow::Result<Ciphertext, anyhow::Error> {
    let r = Fr::rand(rng);
    let r0 = Fr::rand(rng);

    let m_packed: Vec<Fr> = msg
        .as_ref()
        .chunks(block_size)
        .map(Fr::from_le_bytes_mod_order)
        .collect();

    // let domain = vks
    //     .iter()
    //     .map(hash_pk_to_fr)
    //     .collect::<anyhow::Result<Vec<_>, _>>()?;

    let (ss, _) = shamir_ss(rng, r0, threshold, total, None).unwrap();

    let c = G2Affine::generator().mul(r).into_affine();
    let h = G2Affine::rand(rng);
    let c0 = {
        let c0 = h.mul(r) + G2Affine::generator().mul(r);
        c0.into_affine()
    };

    let cjs = vks
        .iter()
        .zip(ss)
        .map(|(vk, s_j)| {
            vk.mul(r).add(&GAffine::G2Affine(
                G2Affine::generator().mul(s_j).into_affine(),
            ))
        })
        .collect_vec();

    let cdashjs = m_packed
        .iter()
        .map(|m_i| {
            let g2_r0 = GAffine::G2Affine(G2Affine::generator().mul(r0).into_affine());
            let h_t_g2_r0 = g2_r0.projective_pairing(id.as_ref()).unwrap();
            let gt_mi = PairingOutput::generator().mul(m_i);
            h_t_g2_r0 + gt_mi
        })
        .collect_vec();

    Ok(Ciphertext {
        id: id.as_ref().to_vec(),
        h: GAffine::G2Affine(h),
        c: GAffine::G2Affine(c),
        c0: GAffine::G2Affine(c0),
        cjs,
        cdashjs,
    })
}

// Returns gt^m (need to calc m = dlog(gt^m))
pub fn decrypt_dlog(
    ct: Ciphertext,
    sigmas: impl IntoIterator<Item = GAffine>,
    share_ids: &[usize],
) -> anyhow::Result<Vec<PairingOutput<ark_ec::bls12::Bls12<ark_bls12_381::Config>>>, anyhow::Error>
{
    // let domain = vks
    //     .iter()
    //     .map(hash_pk_to_fr)
    //     .collect::<anyhow::Result<Vec<_>, _>>()?;

    let basis = lagrange_basis_at_0_for_all::<Fr>(share_ids).unwrap();

    let sigma_thres = sigmas.into_iter().zip_eq(basis.iter().cloned()).fold(
        GAffine::G1Affine(G1Affine::zero()),
        |acc, (sig, l)| {
            let sig_l = sig.mul(l);
            acc.add(&sig_l)
        },
    );

    let sig_c = sigma_thres.pairing(&ct.c).unwrap();

    let c_star = share_ids.iter().zip_eq(basis).fold(
        GAffine::G2Affine(G2Affine::zero()),
        |acc, (i, l_i)| {
            let c_j_l = ct.cjs[i - 1].mul(l_i);
            acc.add(&c_j_l)
        },
    );

    let h_t_c_star = c_star.projective_pairing(&ct.id).unwrap();

    let dis = ct
        .cdashjs
        .into_iter()
        .map(|cdash_j| (cdash_j + sig_c) - h_t_c_star)
        .collect_vec();

    Ok(dis)
}

pub fn decrypt(
    ct: Ciphertext,
    sigmas: impl IntoIterator<Item = GAffine>,
    share_ids: &[usize],
    bits_babygiant: usize,
    total_bits: usize,
    dlp_map: HashMap<PairingOutput<ark_ec::bls12::Bls12<ark_bls12_381::Config>>, u64>,
) -> anyhow::Result<Vec<u8>, anyhow::Error> {
    let dis = decrypt_dlog(ct, sigmas, share_ids)?;

    let msg = dis
        .into_iter()
        .flat_map(|d| {
            babygiant(d, bits_babygiant, total_bits, &dlp_map)
                .to_le_bytes()
                .into_iter()
                .take(total_bits / 8)
        })
        .collect();

    Ok(msg)
}

pub fn sign<I: AsRef<[u8]>>(id: I, sk: Fr) -> Result<GAffine, anyhow::Error> {
    let mapper = MapToCurveBasedHasher::<
        short_weierstrass::Projective<g1::Config>,
        DefaultFieldHasher<sha2::Sha256, 128>,
        WBMap<g1::Config>,
    >::new(G1_DOMAIN)
    .map_err(|_| SWEError::MapperInitialisation {
        hash: "sha2".to_owned(),
        field: "G1".to_owned(),
    })?;
    let ht = G1Projective::from(
        mapper
            .hash(id.as_ref())
            .map_err(|_| SWEError::HashToCurve("G1".to_owned()))?,
    );

    let sigma = ht.mul(sk).into_affine();

    Ok(GAffine::G1Affine(sigma))
}

pub fn shamir_ss<R: RngCore, F: PrimeField>(
    rng: &mut R,
    secret: F,
    threshold: usize,
    total: usize,
    domain: Option<Vec<F>>,
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
    let mut coeffs = Vec::with_capacity(threshold);
    coeffs.append(&mut (0..threshold - 1).map(|_| F::rand(rng)).collect());
    coeffs.insert(0, secret);

    let poly = DensePolynomial::from_coefficients_vec(coeffs);
    let shares = (1..=total)
        .map(|i| poly.evaluate(&domain.as_ref().map_or(F::from(i as u64), |d| d[i - 1])))
        .collect::<Vec<_>>();

    Ok((shares, poly))
}

fn hash_pk_to_fr(p: &GAffine) -> anyhow::Result<Fr, SWEError> {
    let d = sha2::Sha512::digest(p.to_compressed()?).to_vec();
    Ok(Fr::from_le_bytes_mod_order(&d))
}

fn lagrange_basis_at_0_for_all<F: PrimeField>(
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

fn lagrange_basis_at_domain<F: PrimeField>(
    domain: &[F],
    x_coords: &[usize],
) -> Result<Vec<F>, anyhow::Error> {
    let total = domain.len();
    let mut basis = vec![];

    for i in 0..total {
        let mut tmp_l: F = F::one();
        for j in 0..total {
            if i != j {
                tmp_l *= domain[i].neg().div(&(domain[j] - domain[i]));
            }
        }
        basis.push(tmp_l);
    }

    Ok(x_coords.iter().map(|i| basis[i - 1]).collect_vec())
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
    dlp_map: &HashMap<PairingOutput<ark_ec::bls12::Bls12<ark_bls12_381::Config>>, u64>,
) -> u64 {
    let bits_diff = total_bits - bits_babygiant;

    let n = 1u64 << bits_babygiant;

    let mut x = d;
    let tmp = PairingOutput::generator().mul_bigint(BigInt::<1>::from(n));

    let k = 1u64 << bits_diff;
    for i in 0..=k {
        if dlp_map.contains_key(&x) {
            return dlp_map.get(&x).unwrap() + i * n;
        }
        x += tmp;
    }

    0
}


#[cfg(test)]
mod tests {
    use ark_std::{end_timer, start_timer};
    use rand::Rng;

    use super::*;

    #[test]
    fn test_mcfly_simple() {
        const N: usize = 10;
        const T: usize = 5;
        const BLOCK_SIZE: usize = 4;

        let mut rng = ark_std::test_rng();

        let sks = [0; N].map(|_| Fr::from_le_bytes_mod_order(&rng.gen::<[u8; 32]>()));
        let vks = sks.map(|sk| GAffine::G2Affine(G2Affine::generator().mul(sk).into_affine()));

        let msg = b"test_test";
        let id = b"88";

        let ct = encrypt(&vks, id, msg, T, N, &mut rng, BLOCK_SIZE).unwrap();

        // sign

        let share_ids = (1..=T + 1).collect_vec();
        let sigmas = share_ids.iter().map(|i| sign(id, sks[i - 1]).unwrap());

        let d = decrypt_dlog(ct, sigmas, &share_ids).unwrap();

        // check dlog
        let m_packed: Vec<Fr> = msg
            .as_ref()
            .chunks(BLOCK_SIZE)
            .map(Fr::from_le_bytes_mod_order)
            .collect();
        let d_test = m_packed
            .iter()
            .map(|m| PairingOutput::generator().mul(m))
            .collect_vec();

        assert_eq!(d, d_test, "dec_dlog(enc(m)) != gt^m");
    }

    #[test]
    fn test_mcfly_full() {
        const N: usize = 10;
        const T: usize = 5;
        const BITS_BG: usize = 16;
        const BITS_TOTAL: usize = 16; // TODO: it should be possible to use BITS_TOTAL = 24 but babygiant algo fails to recover dlog
        const BLOCK_SIZE: usize = BITS_TOTAL / 8;
        let mut rng = ark_std::test_rng();

        let sks = [0; N].map(|_| Fr::from_le_bytes_mod_order(&rng.gen::<[u8; 32]>()));
        let vks = sks.map(|sk| GAffine::G2Affine(G2Affine::generator().mul(sk).into_affine()));

        let msg = b"test_test";
        let id = b"88";

        let ct = encrypt(&vks, id, msg, T, N, &mut rng, BLOCK_SIZE).unwrap();

        // sign

        let share_ids = (1..=T + 1).collect_vec();
        let sigmas = share_ids.iter().map(|i| sign(id, sks[i - 1]).unwrap());

        let timer = start_timer!(|| "babygiant pre-compute");
        let dlp_map = babygiant_precomp(BITS_BG);
        end_timer!(timer);
        let timer = start_timer!(|| "swe decrtypt");

        let m = decrypt(ct, sigmas, &share_ids, BITS_BG, BITS_TOTAL, dlp_map).unwrap();
        end_timer!(timer);

        let mut msg_padded = msg.to_vec();
        msg_padded.resize(msg.len().div_ceil(BLOCK_SIZE) * BLOCK_SIZE, b'\0');

        assert_eq!(m, msg_padded, "dec(enc(m)) != m");
    }
}
