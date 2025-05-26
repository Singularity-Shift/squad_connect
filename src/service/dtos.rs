use std::fmt;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub enum Network {
    Devnet,
    Testnet,
    Mainnet,
}

#[derive(Debug)]
pub enum EnokiEndpoints {
    Nonce,
    Address,
    ZkProof,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ResponseData<P> {
    pub data: P,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NonceResponse {
    pub nonce: String,
    pub randomness: String,
    pub epoch: u64,
    pub max_epoch: u64,
    pub estimated_expiration: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NoncePayload {
    network: String,
    ephemeral_public_key: String,
    additional_epochs: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZKPPayload {
    network: String,
    ephemeral_public_key: String,
    max_epoch: u64,
    randomness: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountResponse {
    pub salt: String,
    pub address: String,
    pub public_key: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZkLoginInputsCamelCase {
    pub proof_points: ZkLoginProofPointsCamelCase,
    pub iss_base64_details: String,
    pub header_base64: String,
    pub address_seed: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZkLoginProofPointsCamelCase {
    pub a: Vec<String>,
    pub b: Vec<Vec<String>>,
    pub c: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ZkLoginInputsSnakeCase {
    pub proof_points: ZkLoginProofPointsSnakeCase,
    pub iss_base64_details: String,
    pub header_base64: String,
    pub address_seed: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ZkLoginProofPointsSnakeCase {
    pub a: Vec<String>,
    pub b: Vec<Vec<String>>,
    pub c: Vec<String>,
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Network::Devnet => write!(f, "devnet"),
            Network::Testnet => write!(f, "testnet"),
            Network::Mainnet => write!(f, "mainnet"),
        }
    }
}

impl fmt::Display for EnokiEndpoints {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let base_url = String::from("https://api.enoki.mystenlabs.com/v1/zklogin");

        match *self {
            EnokiEndpoints::Nonce => write!(f, "{}/nonce", base_url),
            EnokiEndpoints::Address => write!(f, "{}", base_url),
            EnokiEndpoints::ZkProof => write!(f, "{}/zkp", base_url),
        }
    }
}

impl From<(String, String, u64)> for NoncePayload {
    fn from(nonce_payload: (String, String, u64)) -> Self {
        let (network, ephemeral_public_key, additional_epochs) = nonce_payload;

        NoncePayload {
            network,
            ephemeral_public_key,
            additional_epochs,
        }
    }
}

impl From<(String, String, u64, String)> for ZKPPayload {
    fn from(zkp_payload: (String, String, u64, String)) -> Self {
        let (network, ephemeral_public_key, max_epoch, randomness) = zkp_payload;

        ZKPPayload {
            network,
            ephemeral_public_key,
            max_epoch,
            randomness,
        }
    }
}

impl From<ZkLoginInputsCamelCase> for ZkLoginInputsSnakeCase {
    fn from(camel: ZkLoginInputsCamelCase) -> Self {
        Self {
            proof_points: ZkLoginProofPointsSnakeCase {
                a: camel.proof_points.a,
                b: camel.proof_points.b,
                c: camel.proof_points.c,
            },
            iss_base64_details: camel.iss_base64_details,
            header_base64: camel.header_base64,
            address_seed: camel.address_seed,
        }
    }
}

// Utility function to parse camelCase JSON to snake_case struct
pub fn parse_zklogin_inputs_from_camel_case(json_str: &str) -> Result<ZkLoginInputsSnakeCase, serde_json::Error> {
    let camel_case: ZkLoginInputsCamelCase = serde_json::from_str(json_str)?;
    Ok(camel_case.into())
}

// Utility function to convert camelCase JSON to snake_case JSON
pub fn convert_zklogin_json_camel_to_snake(camel_json: &str) -> Result<String, serde_json::Error> {
    let snake_case = parse_zklogin_inputs_from_camel_case(camel_json)?;
    serde_json::to_string(&snake_case)
}

// Function to convert camelCase JSON to ZkLoginInputs (snake_case)
pub fn convert_camel_case_to_zklogin_inputs(camel_json: &str) -> Result<fastcrypto_zkp::bn254::zk_login::ZkLoginInputs, serde_json::Error> {
    // First parse the camelCase JSON
    let camel_case: ZkLoginInputsCamelCase = serde_json::from_str(camel_json)?;
    
    // Convert to snake_case
    let snake_case: ZkLoginInputsSnakeCase = camel_case.into();
    
    // Serialize to snake_case JSON
    let snake_json = serde_json::to_string(&snake_case)?;
    
    // Deserialize back to the original ZkLoginInputs type
    let zklogin_inputs: fastcrypto_zkp::bn254::zk_login::ZkLoginInputs = serde_json::from_str(&snake_json)?;
    
    Ok(zklogin_inputs)
}
