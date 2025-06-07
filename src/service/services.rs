use std::path::PathBuf;

use super::{
    dtos::{
        AccountResponse, EnokiEndpoints, Network, NoncePayload, NonceResponse, ResponseData,
        SponsorTransactionPayload, SponsorTransactionResponse, SubmitSponsorTransactionPayload,
        SubmitSponsorTransactionResponse, ZKPPayload,
    },
    types::{GoogleOauthProvider, Result, ServiceError},
};
use async_trait::async_trait;
use fastcrypto_zkp::bn254::zk_login::ZkLoginInputs;
use jwt_simple::reexports::rand::{Rng, SeedableRng, rngs::StdRng, thread_rng};
use reqwest::{
    Client,
    header::{HeaderMap, HeaderValue},
};
use serde::{Deserialize, Serialize};
use sui_keys::keystore::{AccountKeystore, FileBasedKeystore};
use sui_sdk::{
    SuiClient,
    types::{
        base_types::SuiAddress,
        crypto::{AccountKeyPair, EncodeDecodeBase64, KeypairTraits, SuiKeyPair},
        transaction::Transaction,
    },
};

/// Squad Connect Services
///
/// This module provides core services for Sui blockchain integration with zkLogin authentication.
/// It handles OAuth flows, JWT processing, ZK proof generation, and transaction management.
///
/// # Features
/// - Google OAuth 2.0 integration
/// - Zero-knowledge proof generation for authentication  
/// - Account management and address derivation
/// - Transaction signing and sponsor transaction support
/// - Automatic error handling with detailed error messages
///
/// # Example
/// ```rust
/// use squad_connect::service::services::Services;
/// use squad_connect::service::dtos::Network;
/// use sui_sdk::SuiClientBuilder;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let sui_client = SuiClientBuilder::default().build_testnet().await?;
///     let services = Services::new(
///         sui_client,
///         Network::Testnet,
///         "your-api-key".to_string(),
///         "your-google-client-id".to_string(),
///     );
///     Ok(())
/// }
/// ```

#[derive(Clone)]
pub struct Services {
    /// Sui blockchain client for network operations
    node: SuiClient,
    /// Target network (Devnet, Testnet, or Mainnet)
    network: Network,
    /// Enoki API key for zkLogin services
    api_key: String,
    /// Google OAuth client ID
    client_id: String,
    /// Random value for ZK proof generation
    randomness: String,
    /// Ephemeral public key for zkLogin
    public_key: String,
    /// Maximum epoch for proof validity
    max_epoch: u64,
    /// OAuth nonce for authentication
    nonce: String,
}

impl Services {
    /// Creates a new Services instance
    ///
    /// # Arguments
    /// * `node` - Sui client for blockchain operations
    /// * `network` - Target network (Devnet, Testnet, Mainnet)
    /// * `api_key` - Enoki API key for zkLogin services
    /// * `client_id` - Google OAuth client ID
    ///
    /// # Example
    /// ```rust
    /// let services = Services::new(
    ///     sui_client,
    ///     Network::Testnet,
    ///     "your-api-key".to_string(),
    ///     "your-google-client-id".to_string(),
    /// );
    /// ```
    pub fn new(node: SuiClient, network: Network, api_key: String, client_id: String) -> Self {
        Self {
            node,
            api_key,
            network,
            client_id,
            randomness: String::from(""),
            public_key: String::from(""),
            max_epoch: 0,
            nonce: String::from(""),
        }
    }

    /// Returns a reference to the Sui client
    ///
    /// # Returns
    /// Reference to the SuiClient for direct blockchain operations
    pub fn get_node(&self) -> &SuiClient {
        &self.node
    }
}

#[async_trait]
impl GoogleOauthProvider for Services {
    /// Generates OAuth URL for Google authentication with zkLogin
    ///
    /// Creates an ephemeral key pair, generates a nonce, and builds the Google OAuth URL
    /// for zkLogin authentication flow.
    ///
    /// # Arguments
    /// * `redirect_url` - URL where Google will redirect after authentication
    /// * `state` - Optional state parameter to maintain across the OAuth flow
    ///
    /// # Returns
    /// Google OAuth URL that user should visit to authenticate
    ///
    /// # Example
    /// ```rust
    /// let oauth_url = services.get_oauth_url(
    ///     "http://localhost:3000/callback".to_string(),
    ///     Some("my_custom_state".to_string())
    /// ).await?;
    /// println!("Visit: {}", oauth_url);
    /// ```
    async fn get_oauth_url<T: Send + Serialize>(
        &mut self,
        redirect_url: String,
        state: Option<T>,
    ) -> Result<String> {
        // Create the ephemeral key pair outside the async block

        // Build the OAuth URL with proper query parameters
        let mut google_url = url::Url::parse("https://accounts.google.com/o/oauth2/v2/auth")
            .map_err(|e| {
                ServiceError::InvalidResponse(format!("Failed to parse OAuth URL: {}", e))
            })?;

        {
            let mut query_pairs = google_url.query_pairs_mut();
            query_pairs.append_pair("client_id", &self.client_id);
            query_pairs.append_pair("response_type", "id_token");
            query_pairs.append_pair("redirect_uri", &redirect_url);
            query_pairs.append_pair("scope", "openid");
            query_pairs.append_pair("nonce", &self.nonce);

            // Add state parameter if provided
            if let Some(state_value) = state {
                let state_json = serde_json::to_string(&state_value).map_err(|e| {
                    ServiceError::InvalidResponse(format!("Failed to serialize state: {}", e))
                })?;
                query_pairs.append_pair("state", &state_json);
            }
        }

        Ok(google_url.to_string())
    }

    /// Extracts JWT token from OAuth callback URL
    ///
    /// Parses the callback URL from Google OAuth and extracts the id_token parameter
    /// which contains the JWT needed for zkLogin proof generation.
    ///
    /// # Arguments  
    /// * `callback_url` - The full callback URL from Google OAuth redirect
    ///
    /// # Returns
    /// The JWT token string extracted from the callback URL
    ///
    /// # Example
    /// ```rust
    /// let callback = "http://localhost:3000/callback#id_token=eyJ...&state=abc";
    /// let jwt = services.extract_jwt_from_callback(callback)?;
    /// ```
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

    /// Creates ephemeral keypair and generates nonce for zkLogin
    ///
    /// This method initializes the zkLogin parameters by:
    /// 1. Generating an ephemeral key pair
    /// 2. Storing it in the provided keystore
    /// 3. Requesting a nonce from Enoki API
    /// 4. Setting up all parameters needed for zkLogin flow
    ///
    /// # Arguments
    /// * `path` - Path to the keystore directory where ephemeral keys will be stored
    ///
    /// # Returns
    /// Result indicating success or failure of the setup process
    ///
    /// # Example
    /// ```rust
    /// let keystore_path = PathBuf::from("./keystore");
    /// services.create_zkp_payload(keystore_path).await?;
    /// ```
    async fn create_zkp_payload(&mut self, path: PathBuf) -> Result<()> {
        let ephemeral_key_pair = {
            let mut seed = [0u8; 32];
            thread_rng().fill(&mut seed);
            SuiKeyPair::Ed25519(AccountKeyPair::generate(&mut StdRng::from_seed(seed)))
        };

        let mut key_store = FileBasedKeystore::new(&path).map_err(|e| {
            ServiceError::InvalidResponse(format!("Failed to create key store: {}", e))
        })?;

        key_store
            .add_key(None, ephemeral_key_pair.copy())
            .map_err(|e| {
                ServiceError::InvalidResponse(format!("Failed to add key to key store: {}", e))
            })?;

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
            .header(
                "Authorization",
                HeaderValue::from_str(&format!("Bearer {}", self.api_key)).unwrap(),
            )
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
        self.nonce = nonce_data.data.nonce;

        Ok(())
    }

    /// Generates zero-knowledge proof for authentication
    ///
    /// Takes a JWT token and generates a zero-knowledge proof that can be used
    /// to authenticate with the Sui blockchain without revealing sensitive information.
    ///
    /// # Arguments
    /// * `jwt` - JWT token received from Google OAuth
    ///
    /// # Returns
    /// ZkLoginInputs containing the proof and necessary parameters
    ///
    /// # Example
    /// ```rust
    /// let zk_inputs = services.zk_proof(&jwt_token).await?;
    /// println!("ZK proof generated successfully");
    /// ```
    async fn zk_proof(&self, jwt: &str) -> Result<ZkLoginInputs> {
        // Validate the JWT and extract claims
        let mut headers = HeaderMap::new();

        headers.insert(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {}", self.api_key)).unwrap(),
        );
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
            let error_body = zk_proof_response
                .text()
                .await
                .unwrap_or_else(|_| "Unable to read error response".to_string());
            return Err(ServiceError::Network(format!(
                "ZK proof request failed with status {}: {}",
                status, error_body
            )));
        }

        let zkp_data: ResponseData<ZkLoginInputs> = zk_proof_response
            .json()
            .await
            .map_err(|e| ServiceError::JwtFormat(format!("Failed json parse: {}", e)))?;

        Ok(zkp_data.data)
    }

    fn extract_state_from_callback<T: for<'de> Deserialize<'de>>(
        &self,
        callback_url: &str,
    ) -> Result<Option<T>> {
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
            }
            None => Ok(None),
        }
    }

    async fn get_account(&self, jwt: &str) -> Result<AccountResponse> {
        let mut headers = HeaderMap::new();

        headers.insert(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {}", self.api_key)).unwrap(),
        );
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
            let error_body = account_response
                .text()
                .await
                .unwrap_or_else(|_| "Unable to read error response".to_string());
            return Err(ServiceError::Network(format!(
                "Account request failed with status {}: {}",
                status, error_body
            )));
        }

        let account_data: ResponseData<AccountResponse> = account_response
            .json()
            .await
            .map_err(|e| ServiceError::JwtFormat(format!("Failed json parse: {}", e)))?;

        Ok(account_data.data)
    }

    fn get_zk_proof_params(&self) -> (String, String, u64) {
        (
            self.randomness.clone(),
            self.public_key.clone(),
            self.max_epoch,
        )
    }

    fn set_zk_proof_params(&mut self, randomness: String, public_key: String, max_epoch: u64) {
        self.randomness = randomness;
        self.public_key = public_key;
        self.max_epoch = max_epoch;
    }

    /// Creates a sponsor transaction for gasless execution
    ///
    /// Submits a transaction to be sponsored by a third party, allowing users
    /// to execute transactions without paying gas fees directly.
    ///
    /// # Arguments
    /// * `transaction` - The transaction to be sponsored
    /// * `sender` - Address of the transaction sender
    /// * `allowed_addresses` - List of addresses allowed to interact with
    /// * `allowed_move_call_targets` - List of allowed Move function calls
    ///
    /// # Returns
    /// SponsorTransactionResponse containing digest and transaction bytes
    ///
    /// # Example
    /// ```rust
    /// let response = services.create_sponsor_transaction(
    ///     transaction,
    ///     sender_address,
    ///     vec!["0x123...".to_string()],
    ///     vec!["0xabc::module::function".to_string()],
    /// ).await?;
    /// ```
    async fn create_sponsor_transaction(
        &mut self,
        transaction: Transaction,
        sender: SuiAddress,
        allowed_addresses: Vec<String>,
        allowed_move_call_targets: Vec<String>,
    ) -> Result<SponsorTransactionResponse> {
        let mut headers = HeaderMap::new();

        headers.insert(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {}", self.api_key)).unwrap(),
        );

        let (tx_bytes_base64, _signatures) = transaction.to_tx_bytes_and_signatures();

        let sponsor_transaction_payload = SponsorTransactionPayload::from((
            self.network.to_string(),
            tx_bytes_base64,
            sender.to_string(),
            allowed_addresses,
            allowed_move_call_targets,
        ));

        let sponsor_transaction_response = Client::new()
            .post(&EnokiEndpoints::CreateSponsorTransaction.to_string())
            .headers(headers)
            .json(&sponsor_transaction_payload)
            .send()
            .await
            .map_err(|e| ServiceError::Network(format!("Failed to send request: {}", e)))?;

        if !sponsor_transaction_response.status().is_success() {
            let status = sponsor_transaction_response.status();
            let error_body = sponsor_transaction_response
                .text()
                .await
                .unwrap_or_else(|_| "Unable to read error response".to_string());
            return Err(ServiceError::Network(format!(
                "Sponsor transaction request failed with status {}: {}",
                status, error_body
            )));
        }

        let sponsor_transaction_data: ResponseData<SponsorTransactionResponse> =
            sponsor_transaction_response
                .json()
                .await
                .map_err(|e| ServiceError::JwtFormat(format!("Failed json parse: {}", e)))?;

        Ok(sponsor_transaction_data.data)
    }

    async fn submit_sponsor_transaction(
        &mut self,
        digest: String,
        signature: String,
    ) -> Result<SubmitSponsorTransactionResponse> {
        let mut headers = HeaderMap::new();

        headers.insert(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {}", self.api_key)).unwrap(),
        );

        let submit_sponsor_transaction_payload = SubmitSponsorTransactionPayload::from(signature);

        let submit_sponsor_transaction_response = Client::new()
            .post(&EnokiEndpoints::SubmitSponsorTransaction(digest).to_string())
            .headers(headers)
            .json(&submit_sponsor_transaction_payload)
            .send()
            .await
            .map_err(|e| ServiceError::Network(format!("Failed to send request: {}", e)))?;

        if !submit_sponsor_transaction_response.status().is_success() {
            let status = submit_sponsor_transaction_response.status();
            let error_body = submit_sponsor_transaction_response
                .text()
                .await
                .unwrap_or_else(|_| "Unable to read error response".to_string());
            return Err(ServiceError::Network(format!(
                "Submit sponsor transaction request failed with status {}: {}",
                status, error_body
            )));
        }

        let submit_sponsor_transaction_data: ResponseData<SubmitSponsorTransactionResponse> =
            submit_sponsor_transaction_response
                .json()
                .await
                .map_err(|e| ServiceError::JwtFormat(format!("Failed json parse: {}", e)))?;

        Ok(submit_sponsor_transaction_data.data)
    }
}
