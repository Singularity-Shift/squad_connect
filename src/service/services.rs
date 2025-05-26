use super::{
    dtos::{
        AccountResponse, EnokiEndpoints, Network, NoncePayload, NonceResponse, ResponseData, ZKPPayload,
    },
    types::{GoogleOauthProvider, Result, ServiceError},
};
use async_trait::async_trait;
use fastcrypto_zkp::bn254::zk_login::ZkLoginInputs;
use jwt_simple::reexports::rand::{Rng, SeedableRng, rngs::StdRng, thread_rng};
use reqwest::{Client, header::{HeaderMap, HeaderValue}};
use serde::{Serialize, Deserialize};
use sui_sdk::{
    types::{
        base_types::SuiAddress,
        crypto::{AccountKeyPair, EncodeDecodeBase64, KeypairTraits, SuiKeyPair},
    }, SuiClient
};

#[derive(Clone)]
pub struct Services {
    node: SuiClient,
    network: Network,
    api_key: String,
    client_id: String,
    randomness: String,
    public_key: String,
    max_epoch: u64,
}

impl Services {
    pub fn new(node: SuiClient, network: Network, api_key: String, client_id: String) -> Self {
        Self {
            node,
            api_key,
            network,
            client_id,
            randomness: String::from(""),
            public_key: String::from(""),
            max_epoch: 0,
        }
    }

    pub fn get_node(&self) -> &SuiClient {
        &self.node
    }
}

#[async_trait]
impl GoogleOauthProvider for Services {
    async fn get_oauth_url<T: Send + Serialize>(&mut self, redirect_url: String, state: Option<T>) -> Result<String> {
        // Create the ephemeral key pair outside the async block
        let ephemeral_key_pair = {
            let mut seed = [0u8; 32];
            thread_rng().fill(&mut seed);
            SuiKeyPair::Ed25519(AccountKeyPair::generate(&mut StdRng::from_seed(seed)))
        };

        // Generate randomness outside the async block
        let mut randomness = [0u8; 16];
        {
            let mut rng = thread_rng();
            rng.fill(&mut randomness);
        }

        let payload = NoncePayload::from((
            self.network.to_string(),
            ephemeral_key_pair.public().encode_base64(),
            2,
        ));

        let nonce_response = Client::new()
            .post(EnokiEndpoints::Nonce.to_string())
            .json(&payload)
            .header("Authorization", HeaderValue::from_str(&format!("Bearer {}", self.api_key)).unwrap())
            .send()
            .await
            .map_err(|e| ServiceError::Network(format!("Failed to send request: {}", e)))?;

        let nonce_data: ResponseData<NonceResponse> = nonce_response
            .json()
            .await
            .map_err(|e| ServiceError::JwtFormat(format!("Failed json parse: {}", e)))?;

        self.randomness = nonce_data.data.randomness;
        self.public_key = ephemeral_key_pair.public().encode_base64();
        self.max_epoch = nonce_data.data.max_epoch;

        // Build the OAuth URL with proper query parameters
        let mut google_url = url::Url::parse("https://accounts.google.com/o/oauth2/v2/auth")
            .map_err(|e| ServiceError::InvalidResponse(format!("Failed to parse OAuth URL: {}", e)))?;

        {
            let mut query_pairs = google_url.query_pairs_mut();
            query_pairs.append_pair("client_id", &self.client_id);
            query_pairs.append_pair("response_type", "id_token");
            query_pairs.append_pair("redirect_uri", &redirect_url);
            query_pairs.append_pair("scope", "openid");
            query_pairs.append_pair("nonce", &nonce_data.data.nonce);
            
            // Add state parameter if provided
            if let Some(state_value) = state {
                let state_json = serde_json::to_string(&state_value)
                    .map_err(|e| ServiceError::InvalidResponse(format!("Failed to serialize state: {}", e)))?;
                query_pairs.append_pair("state", &state_json);
            }
        }

        Ok(google_url.to_string())
    }

    fn extract_jwt_from_callback(&self, callback_url: &str) -> Result<String> {
        // Parse the callback URL
        let url = url::Url::parse(callback_url).map_err(|e| {
            ServiceError::JwtExtraction(format!("Failed to parse callback URL: {}", e))
        })?;

        // Extract the id_token parameter
        let id_token = url
            .query_pairs()
            .find(|(key, _)| key == "id_token")
            .map(|(_, value)| value.to_string())
            .ok_or_else(|| {
                ServiceError::JwtExtraction("No id_token found in callback URL".to_string())
            })?;

        Ok(id_token)
    }

    fn set_zk_proof_params(&mut self, network: Network, public_key: String, max_epoch: u64, randomness: String) {
        self.network = network;
        self.public_key = public_key;
        self.max_epoch = max_epoch;
        self.randomness = randomness;
    }

    fn get_zk_proof_params(&self) -> (Network, String, u64, String) {
        (self.network.clone(), self.public_key.clone(), self.max_epoch, self.randomness.clone())
    }

    async fn zk_proof(&self, jwt: &str) -> Result<ZkLoginInputs> {
        // Validate the JWT and extract claims
        let mut headers = HeaderMap::new();

        headers.insert("Authorization", HeaderValue::from_str(&format!("Bearer {}", self.api_key)).unwrap());
        headers.insert("zklogin-jwt", jwt.parse().unwrap());

        let zkp_payload = ZKPPayload::from((
            self.network.to_string(),
            self.public_key.clone(),
            self.max_epoch,
            self.randomness.clone(),
        ));

        let zk_proof_response = Client::new()
            .post(&EnokiEndpoints::ZkProof.to_string())
            .headers(headers)
            .json(&zkp_payload)
            .send()
            .await
            .map_err(|e| ServiceError::Network(format!("Failed to send request: {}", e)))?;

        if !zk_proof_response.status().is_success() {
            let status = zk_proof_response.status();
            let error_body = zk_proof_response.text().await
                .unwrap_or_else(|_| "Unable to read error response".to_string());
            return Err(ServiceError::Network(format!(
                "ZK proof request failed with status {}: {}", 
                status, 
                error_body
            )));
        }

        let zkp_data: ResponseData<ZkLoginInputs> = zk_proof_response
            .json()
            .await
            .map_err(|e| ServiceError::JwtFormat(format!("Failed json parse: {}", e)))?;

        Ok(zkp_data.data)
    }

    fn get_sui_address(&self, zklogin: ZkLoginInputs) -> SuiAddress {
        SuiAddress::try_from_padded(&zklogin).unwrap()
    }

    fn extract_state_from_callback<T: for<'de> Deserialize<'de>>(&self, callback_url: &str) -> Result<Option<T>> {
        // Parse the callback URL
        let url = url::Url::parse(callback_url).map_err(|e| {
            ServiceError::JwtExtraction(format!("Failed to parse callback URL: {}", e))
        })?;

        // Extract the state parameter
        let state_str = url
            .query_pairs()
            .find(|(key, _)| key == "state")
            .map(|(_, value)| value.to_string());

        match state_str {
            Some(state_json) => {
                let state: T = serde_json::from_str(&state_json).map_err(|e| {
                    ServiceError::JwtExtraction(format!("Failed to deserialize state: {}", e))
                })?;
                Ok(Some(state))
            },
            None => Ok(None),
        }
    }

    async fn get_account(&self, jwt: &str) -> Result<AccountResponse> {
        let mut headers = HeaderMap::new();

        headers.insert("Authorization", HeaderValue::from_str(&format!("Bearer {}", self.api_key)).unwrap());
        headers.insert("zklogin-jwt", jwt.parse().unwrap());

        let account_response = Client::new()
            .get(&EnokiEndpoints::Address.to_string())
            .headers(headers)
            .send()
            .await
            .map_err(|e| ServiceError::Network(format!("Failed to send request: {}", e)))?;

        // Check if the response status indicates an error
        if !account_response.status().is_success() {
            let status = account_response.status();
            let error_body = account_response.text().await
                .unwrap_or_else(|_| "Unable to read error response".to_string());
            return Err(ServiceError::Network(format!(
                "Account request failed with status {}: {}", 
                status, 
                error_body
            )));
        }

        let account_data: ResponseData<AccountResponse> = account_response
            .json()
            .await
            .map_err(|e| ServiceError::JwtFormat(format!("Failed json parse: {}", e)))?;

        Ok(account_data.data)
    }
}
