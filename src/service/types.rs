use std::path::PathBuf;

use async_trait::async_trait;
use fastcrypto_zkp::bn254::zk_login::ZkLoginInputs;
use serde::{Deserialize, Serialize};
use sui_sdk::types::{base_types::SuiAddress, transaction::Transaction};
use thiserror::Error;

use super::dtos::{AccountResponse, SponsorTransactionResponse, SubmitSponsorTransactionResponse};

#[derive(Error, Debug)]
pub enum ServiceError {
    #[error("Service error: {0}")]
    Service(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    #[error("Invalid proof: {0}")]
    InvalidProof(String),

    #[error("Invalid JSON format: {0}")]
    JwtFormat(String),

    #[error("Invalid JWT extraction: {0}")]
    JwtExtraction(String),
}

pub type Result<T> = std::result::Result<T, ServiceError>;

#[async_trait]
pub trait GoogleOauthProvider {
    async fn get_oauth_url<T: Send + Serialize>(
        &mut self,
        redirect_url: String,
        state: Option<T>,
    ) -> Result<String>;
    fn extract_jwt_from_callback(&self, callback_url: &str) -> Result<String>;
    fn extract_state_from_callback<T: for<'de> Deserialize<'de>>(
        &self,
        callback_url: &str,
    ) -> Result<Option<T>>;
    async fn zk_proof(&self, jwt: &str) -> Result<ZkLoginInputs>;
    async fn get_account(&self, jwt: &str) -> Result<AccountResponse>;
    async fn create_zkp_payload(&mut self, path: PathBuf) -> Result<()>;
    async fn create_sponsor_transaction(
        &mut self,
        transaction: Transaction,
        sender: SuiAddress,
        allowed_addresses: Vec<String>,
        allowed_move_call_targets: Vec<String>,
    ) -> Result<SponsorTransactionResponse>;

    async fn submit_sponsor_transaction(
        &mut self,
        digest: String,
        signature: String,
    ) -> Result<SubmitSponsorTransactionResponse>;
}
