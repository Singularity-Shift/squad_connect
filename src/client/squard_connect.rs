use crate::service::{
    dtos::AccountResponse, services::Services, types::{GoogleOauthProvider, Result}
};
use fastcrypto_zkp::bn254::zk_login::ZkLoginInputs;
use sui_sdk::{SuiClient, types::base_types::SuiAddress};
use serde::{Serialize, Deserialize};

use crate::service::dtos::Network;

#[derive(Clone)]
pub struct SquardConnect {
    services: Services,
    jwt: String,
    zklogin: Option<ZkLoginInputs>,
}

impl SquardConnect {
    pub fn new(node: SuiClient, client_id: String, network: Network, api_key: String) -> Self {
        let services = Services::new(node, network, api_key, client_id);
        Self {
            services,
            jwt: String::new(),
            zklogin: None,
        }
    }

    pub fn get_node(&self) -> &SuiClient {
        &self.services.get_node()
    }

    pub fn set_jwt(&mut self, jwt: String) {
        self.jwt = jwt;
    }

    pub fn set_zk_proof_params(&mut self, network: Network, public_key: String, max_epoch: u64, randomness: String) {
        self.services.set_zk_proof_params(network, public_key, max_epoch, randomness);
    }

    pub fn get_zk_proof_params(&self) -> (Network, String, u64, String) {
        self.services.get_zk_proof_params()
    }

    pub async fn get_url<T: Send + Serialize>(&mut self, redirect_url: String, state: Option<T>) -> Result<String> {
        let url = self.services.get_oauth_url(redirect_url, state).await?;

        Ok(url)
    }

    pub async fn set_zk_login(&mut self, callback_url: String) -> Result<ZkLoginInputs> {
        let jwt = self.services.extract_jwt_from_callback(&callback_url)?;
        self.jwt = jwt;

        let zkpresponse = self.services.zk_proof(&self.jwt).await?;
        self.zklogin = Some(zkpresponse.clone());

        Ok(zkpresponse)
    }

    pub fn get_sui_address(&self) -> Option<SuiAddress> {
        self.zklogin.clone().map(|zklogin| self.services.get_sui_address(zklogin))
    }
    

    pub async fn recover_seed_address(&self) -> Result<ZkLoginInputs> {
        let zkresponse = self.services.zk_proof(&self.jwt).await?;

        Ok(zkresponse)
    }

    pub fn extract_state_from_callback<T: for<'de> Deserialize<'de>>(&self, callback_url: &str) -> Result<Option<T>> {
        self.services.extract_state_from_callback(callback_url)
    }

    pub async fn get_address(&self) -> Result<AccountResponse> {
        let account = self.services.get_account(&self.jwt).await?;

        Ok(account)
    }
}
