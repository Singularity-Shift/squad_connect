use crate::service::{
    services::Services,
    types::{GoogleOauthProvider, Result},
};
use sui_sdk::{SuiClient, types::base_types::SuiAddress};

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

    pub async fn get_url(&mut self, redirect_url: String) -> Result<String> {
        let url = self.services.get_oauth_url(redirect_url).await?;

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
}
