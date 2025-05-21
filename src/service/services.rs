use super::{
    dtos::{
        EnokiEndpoints, Network, NoncePayload, NonceResponse, ResponseData, ZKPPayload, ZKPResponse,
    },
    types::{GoogleOauthProvider, Result, ServiceError},
};
use async_trait::async_trait;
use jwt_simple::reexports::rand::{Rng, SeedableRng, rngs::StdRng, thread_rng};
use reqwest::{Client, header::HeaderMap};
use sui_sdk::{
    SuiClient,
    types::{
        base_types::SuiAddress,
        crypto::{AccountKeyPair, EncodeDecodeBase64, KeypairTraits, SuiKeyPair},
    },
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
    async fn get_oauth_url(&mut self, redirect_url: String) -> Result<String> {
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
            .header("Authorization", format!("Bearer {}", self.api_key))
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

        let google_url = format!(
            "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&response_type=id_token&redirect_uri={}&scope=openid&nonce={}",
            self.client_id, redirect_url, nonce_data.data.nonce
        );

        Ok(google_url)
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

    async fn zk_proof(&self, jwt: &str) -> Result<SuiAddress> {
        // Validate the JWT and extract claims
        let mut headers = HeaderMap::new();

        headers.insert("Authorization", self.api_key.parse().unwrap());
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

        let zkp_data: ResponseData<ZKPResponse> = zk_proof_response
            .json()
            .await
            .map_err(|e| ServiceError::JwtFormat(format!("Failed json parse: {}", e)))?;

        Ok(SuiAddress::from_bytes(zkp_data.data.address_seed).unwrap())
    }
}
