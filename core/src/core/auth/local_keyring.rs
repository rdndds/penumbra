/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/
use async_trait::async_trait;
use num_bigint::BigUint;

use crate::core::auth::keys::SLA_KEYS;
use crate::core::auth::{SignRequest, Signer};
use crate::error::{Error, Result};
use crate::utilities::patching::{HEX_NOT_FOUND, contains_bytes};
use crate::utilities::rsa::{RsaPrivateKey, rsa_oaep_encrypt};

pub struct LocalKeyring {
    /// The private key used for signing.
    /// In MTK SLA flow, signing is performed by encrypting data with the private key.
    /// The corresponding public key is used for verification.
    keys: Vec<RsaPrivateKey>,
}

#[async_trait]
impl Signer for LocalKeyring {
    async fn sign(&self, req: &SignRequest) -> Result<Vec<u8>> {
        let key = self
            .keys
            .iter()
            .find(|k| contains_bytes(&req.pubk_mod, &k.n().to_bytes_be()) != HEX_NOT_FOUND)
            .ok_or_else(|| Error::penumbra("No matching key found"))?;

        let signature = rsa_oaep_encrypt(&req.data.rnd, &key.n, &key.d);
        Ok(signature)
    }

    fn can_handle(&self, pubk_mod: &[u8]) -> bool {
        self.keys.iter().any(|k| contains_bytes(pubk_mod, &k.n().to_bytes_be()) != HEX_NOT_FOUND)
    }

    async fn is_authorized(&self, _req: &SignRequest) -> bool {
        true
    }
}

impl LocalKeyring {
    pub fn new() -> Self {
        let keys = SLA_KEYS
            .iter()
            .map(|raw_key| {
                // It's fine here to panic on invalid keys, since these are hardcoded, so in case
                // of an error, we want to catch it :)
                let n = BigUint::parse_bytes(raw_key.n.as_bytes(), 16).expect("Invalid hex in n");
                let d = BigUint::parse_bytes(raw_key.d.as_bytes(), 16).expect("Invalid hex in d");

                RsaPrivateKey::new(n, d)
            })
            .collect();

        LocalKeyring { keys }
    }
}

impl Default for LocalKeyring {
    fn default() -> Self {
        Self::new()
    }
}
