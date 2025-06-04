use std::{path::PathBuf, str::FromStr};

use crate::service::{
    dtos::AccountResponse,
    services::Services,
    types::{GoogleOauthProvider, Result, ServiceError},
};
use fastcrypto_zkp::bn254::zk_login::ZkLoginInputs;
use serde::{Deserialize, Serialize};
use shared_crypto::intent::Intent;
use sui_keys::keystore::{AccountKeystore, FileBasedKeystore};
use sui_sdk::{
    SuiClient,
    types::{
        base_types::SuiAddress,
        crypto::PublicKey,
        signature::GenericSignature,
        transaction::{Transaction, TransactionData},
        zk_login_authenticator::ZkLoginAuthenticator,
    },
};

use crate::service::dtos::Network;

#[derive(Clone)]
pub struct SquardConnect {
    services: Services,
    jwt: String,
}

impl SquardConnect {
    pub fn new(node: SuiClient, client_id: String, network: Network, api_key: String) -> Self {
        let services = Services::new(node, network, api_key, client_id);
        Self {
            services,
            jwt: String::new(),
        }
    }

    pub fn get_node(&self) -> &SuiClient {
        &self.services.get_node()
    }

    pub fn get_max_epoch(&self) -> u64 {
        self.services.get_max_epoch()
    }

    pub fn get_public_key(&self) -> String {
        self.services.get_public_key()
    }

    pub fn set_jwt(&mut self, jwt: String) {
        self.jwt = jwt;
    }

    pub async fn create_zkp_payload(&mut self, path: PathBuf) -> Result<()> {
        self.services.create_zkp_payload(path).await?;

        Ok(())
    }

    pub async fn get_url<T: Send + Serialize>(
        &mut self,
        redirect_url: String,
        state: Option<T>,
    ) -> Result<String> {
        let url = self.services.get_oauth_url(redirect_url, state).await?;

        Ok(url)
    }

    pub async fn recover_seed_address(&self) -> Result<ZkLoginInputs> {
        let zkresponse = self.services.zk_proof(&self.jwt).await?;

        Ok(zkresponse)
    }

    pub fn extract_state_from_callback<T: for<'de> Deserialize<'de>>(
        &self,
        callback_url: &str,
    ) -> Result<Option<T>> {
        self.services.extract_state_from_callback(callback_url)
    }

    pub async fn get_address(&self) -> Result<AccountResponse> {
        let account = self.services.get_account(&self.jwt).await?;

        Ok(account)
    }

    pub async fn get_signer(&self, account: AccountResponse) -> Result<SuiAddress> {
        let public_key = PublicKey::from_str(&account.public_key).map_err(|e| {
            ServiceError::InvalidResponse(format!("Failed to parse public key: {}", e))
        })?;

        let signer = SuiAddress::from(&public_key);

        Ok(signer)
    }

    pub async fn get_sender(&self, account: AccountResponse) -> Result<SuiAddress> {
        let sender = SuiAddress::from_str(&account.address)
            .map_err(|e| ServiceError::InvalidResponse(format!("Failed to parse sender: {}", e)))?;

        Ok(sender)
    }

    pub async fn sign_transaction(
        &self,
        tx: TransactionData,
        account: AccountResponse,
        zk_login_inputs: ZkLoginInputs,
        max_epoch: u64,
        path: PathBuf,
    ) -> Result<Transaction> {
        let signer = self.get_signer(account).await?;

        let key_store = FileBasedKeystore::new(&path).map_err(|e| {
            ServiceError::InvalidResponse(format!("Failed to create key store: {}", e))
        })?;

        let signature = key_store
            .sign_secure(&signer, &tx, Intent::sui_transaction())
            .map_err(|e| {
                ServiceError::InvalidResponse(format!("Failed to sign transaction: {}", e))
            })?;

        let zk_login_authentication =
            ZkLoginAuthenticator::new(zk_login_inputs, max_epoch, signature);

        let generic_signature = GenericSignature::ZkLoginAuthenticator(zk_login_authentication);

        let transaction = Transaction::from_generic_sig_data(tx, vec![generic_signature]);

        Ok(transaction)
    }

    pub async fn sponsor_transaction(
        &mut self,
        tx: Transaction,
        account: AccountResponse,
        allowed_addresses: Vec<String>,
        allowed_move_call_targets: Vec<String>,
    ) -> Result<String> {
        let sender = self.get_sender(account).await?;

        let sponsor_transaction = self
            .services
            .create_sponsor_transaction(tx, sender, allowed_addresses, allowed_move_call_targets)
            .await?;

        let result = self
            .services
            .submit_sponsor_transaction(sponsor_transaction.digest, sponsor_transaction.bytes)
            .await?;

        Ok(result.digest)
    }
}
