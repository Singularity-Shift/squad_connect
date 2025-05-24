use crate::service::{
    dtos::AccountResponse, services::Services, types::{GoogleOauthProvider, Result}
};
use sui_sdk::{SuiClient, types::base_types::SuiAddress};
use serde::{Serialize, Deserialize};

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

    pub fn set_jwt(&mut self, jwt: String) {
        self.jwt = jwt;
    }

    pub async fn get_url<T: Send + Serialize>(&mut self, redirect_url: String, state: Option<T>) -> Result<String> {
        let url = self.services.get_oauth_url(redirect_url, state).await?;

        Ok(url)
    }

    pub async fn get_account(&mut self, callback_url: String) -> Result<SuiAddress> {
        let jwt = self.services.extract_jwt_from_callback(&callback_url)?;
        self.jwt = jwt;

        let account = self.services.zk_proof(&self.jwt).await?;

        Ok(account)
    }

    

    pub async fn recover_account(&self) -> Result<SuiAddress> {
        let address_response = self.services.zk_proof(&self.jwt).await?;

        Ok(address_response)
    }

    pub fn extract_state_from_callback<T: for<'de> Deserialize<'de>>(&self, callback_url: &str) -> Result<Option<T>> {
        self.services.extract_state_from_callback(callback_url)
    }

    pub async fn get_address(&self) -> Result<AccountResponse> {
        let account = self.services.get_account(&self.jwt).await?;

        Ok(account)
    }
}
