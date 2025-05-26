use async_trait::async_trait;
use sui_sdk::{types::base_types::SuiAddress};
use thiserror::Error;
use serde::{Serialize, Deserialize};
use fastcrypto_zkp::bn254::zk_login::ZkLoginInputs;

use super::dtos::{AccountResponse, Network, };

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
    async fn get_oauth_url<T: Send + Serialize>(&mut self, redirect_url: String, state: Option<T>) -> Result<String>;
    fn extract_jwt_from_callback(&self, callback_url: &str) -> Result<String>;
    fn extract_state_from_callback<T: for<'de> Deserialize<'de>>(&self, callback_url: &str) -> Result<Option<T>>;
    fn get_sui_address(&self, address_seed: ZkLoginInputs) -> SuiAddress;
    fn set_zk_proof_params(&mut self, network: Network, public_key: String, max_epoch: u64, randomness: String);
    fn get_zk_proof_params(&self) -> (Network, String, u64, String);
    async fn zk_proof(&self, jwt: &str) -> Result<ZkLoginInputs>;
    async fn get_account(&self, jwt: &str) -> Result<AccountResponse>;
}
