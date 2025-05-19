use crate::service::{
    dtos::AddressResponse,
    services::Services,
    types::{GoogleOauthProvider, Result},
};
use sui_sdk::{SuiClient, types::base_types::SuiAddress};

use crate::service::dtos::Network;

pub struct SquardConnect {
    services: Services,
}

impl SquardConnect {
    pub fn new(node: SuiClient, client_id: String, network: Network, api_key: String) -> Self {
        let services = Services::new(node, network, api_key, client_id);
        Self { services }
    }

    pub async fn get_url(&mut self, redirect_url: String) -> Result<String> {
        let url = self.services.get_oauth_url(redirect_url).await?;

        Ok(url)
    }

    pub async fn get_address(&self, callback_url: String) -> Result<SuiAddress> {
        let jwt = self.services.extract_jwt_from_callback(&callback_url)?;

        let address = self.services.zk_proof(&jwt).await?;

        Ok(address)
    }

    pub async fn recover_address(&self, jwt: &str) -> Result<AddressResponse> {
        let address_response = self.services.get_address(jwt).await?;

        Ok(address_response)
    }
}
