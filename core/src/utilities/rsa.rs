/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/
use num_bigint::BigUint;
use rand::TryRngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

pub struct RsaPrivateKey {
    pub n: BigUint,
    pub d: BigUint,
}

impl RsaPrivateKey {
    pub fn new(n: BigUint, d: BigUint) -> Self {
        RsaPrivateKey { n, d }
    }

    pub fn n(&self) -> &BigUint {
        &self.n
    }

    pub fn d(&self) -> &BigUint {
        &self.d
    }
}

/// Mask Generation Function 1 (MGF1) using SHA-256
fn mgf1(seed: &[u8], mask_len: usize) -> Vec<u8> {
    let mut mask = Vec::with_capacity(mask_len);
    let mut counter = 0u32;

    while mask.len() < mask_len {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(counter.to_be_bytes());
        let hash = hasher.finalize();
        let remaining = mask_len - mask.len();
        mask.extend_from_slice(&hash[..remaining.min(hash.len())]);
        counter += 1;
    }

    mask
}

/// OAEP Encoding with SHA-256
pub fn oaep_encode(message: &[u8], k: usize) -> Vec<u8> {
    let l_hash = Sha256::digest([]);

    let ps_len = k - message.len() - 2 * 32 - 2;
    let mut db = Vec::with_capacity(k - 32 - 1);
    db.extend_from_slice(&l_hash);
    db.extend(vec![0u8; ps_len]);
    db.push(1);
    db.extend_from_slice(message);

    let mut seed = [0u8; 32];
    OsRng.try_fill_bytes(&mut seed).ok();

    let db_mask = mgf1(&seed, k - 32 - 1);
    let masked_db: Vec<u8> = db.iter().zip(db_mask.iter()).map(|(a, b)| a ^ b).collect();

    let seed_mask = mgf1(&masked_db, 32);
    let masked_seed: Vec<u8> = seed.iter().zip(seed_mask.iter()).map(|(a, b)| a ^ b).collect();

    let mut em = Vec::with_capacity(k);
    em.push(0);
    em.extend_from_slice(&masked_seed);
    em.extend_from_slice(&masked_db);
    em
}

pub fn rsa_private_encrypt(encoded: &[u8], n: &BigUint, exp: &BigUint) -> Vec<u8> {
    let m = BigUint::from_bytes_be(encoded);
    let c = m.modpow(exp, n);
    let mut out = c.to_bytes_be();

    let k = n.bits().div_ceil(8) as usize;
    if out.len() < k {
        let mut padded = vec![0u8; k - out.len()];
        padded.extend_from_slice(&out);
        out = padded;
    }
    out
}

pub fn rsa_oaep_encrypt(message: &[u8], n: &BigUint, exp: &BigUint) -> Vec<u8> {
    let k = n.bits().div_ceil(8);
    let encoded = oaep_encode(message, k as usize);
    rsa_private_encrypt(&encoded, n, exp)
}
