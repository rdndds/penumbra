/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/
use std::sync::{Arc, OnceLock, RwLock};

use async_trait::async_trait;

#[cfg(not(feature = "no_localslakeyring"))]
use crate::core::auth::local_keyring::LocalKeyring;
use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignPurpose {
    BromSla,
    DaSla,
}

pub struct SignRequest {
    pub data: Vec<u8>,
    pub purpose: SignPurpose,
    pub pubk_mod: Vec<u8>,
}

#[async_trait]
pub trait Signer: Send + Sync {
    fn can_sign(&self, req: &SignRequest) -> bool;
    async fn sign(&self, req: &SignRequest) -> Result<Vec<u8>>;
}

pub struct AuthManager {
    signers: RwLock<Vec<Arc<dyn Signer>>>,
}

static INSTANCE: OnceLock<AuthManager> = OnceLock::new();

impl AuthManager {
    /// Get the global AuthManager instance.
    pub fn get() -> &'static AuthManager {
        INSTANCE.get_or_init(|| {
            #[allow(unused_mut)]
            let mut default_signers: Vec<Arc<dyn Signer>> = Vec::new();

            #[cfg(not(feature = "no_localslakeyring"))]
            {
                let local_keyring = Arc::new(LocalKeyring::new());
                default_signers.push(local_keyring);
            }

            AuthManager { signers: RwLock::new(default_signers) }
        })
    }

    /// Registers a new signer to be available for signing requests.
    pub fn register_signer(&self, signer: Arc<dyn Signer>) -> Result<()> {
        let mut signers = self.signers.write()?;
        signers.push(signer);

        Ok(())
    }

    /// Return whether any of the registered signers can sign the given request.
    pub fn can_sign(&self, req: &SignRequest) -> bool {
        let signers = match self.signers.read() {
            Ok(signers) => signers,
            Err(_) => return false,
        };

        signers.iter().any(|signer| signer.can_sign(req))
    }

    /// Signs the given request using the first capable signer.
    pub async fn sign(&self, req: &SignRequest) -> Result<Vec<u8>> {
        let signer = {
            let list = self.signers.read()?;
            list.iter().find(|s| s.can_sign(req)).cloned()
        };

        match signer {
            Some(s) => s.sign(req).await,
            None => Err(Error::penumbra("Could not find any signer")),
        }
    }
}
