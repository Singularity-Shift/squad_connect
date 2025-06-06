use serde::{Deserialize, Serialize};
use std::fmt;

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
    CreateSponsorTransaction,
    SubmitSponsorTransaction(String),
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

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SponsorTransactionPayload {
    network: String,
    transaction_block_kind_bytes: String,
    sender: String,
    allowed_addresses: Vec<String>,
    allowed_move_call_targets: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SponsorTransactionResponse {
    pub digest: String,
    pub bytes: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitSponsorTransactionPayload {
    signature: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitSponsorTransactionResponse {
    pub digest: String,
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

impl From<String> for Network {
    fn from(network: String) -> Self {
        match network.as_str() {
            "devnet" => Network::Devnet,
            "testnet" => Network::Testnet,
            "mainnet" => Network::Mainnet,
            _ => Network::Testnet, // Default to testnet for unknown values
        }
    }
}

impl fmt::Display for EnokiEndpoints {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let base_url = String::from("https://api.enoki.mystenlabs.com/v1");

        match self {
            EnokiEndpoints::Nonce => write!(f, "{}/zklogin/nonce", base_url),
            EnokiEndpoints::Address => write!(f, "{}/zklogin", base_url),
            EnokiEndpoints::ZkProof => write!(f, "{}/zklogin/zkp", base_url),
            EnokiEndpoints::CreateSponsorTransaction => {
                write!(f, "{}/transaction-blocks/sponsor", base_url)
            }
            EnokiEndpoints::SubmitSponsorTransaction(digest) => {
                write!(f, "{}/transaction-blocks/sponsor/{}", base_url, digest)
            }
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

impl From<(String, String, String, Vec<String>, Vec<String>)> for SponsorTransactionPayload {
    fn from(
        sponsor_transaction_payload: (String, String, String, Vec<String>, Vec<String>),
    ) -> Self {
        let (
            network,
            transaction_block_kind_bytes,
            sender,
            allowed_addresses,
            allowed_move_call_targets,
        ) = sponsor_transaction_payload;

        SponsorTransactionPayload {
            network,
            transaction_block_kind_bytes,
            sender,
            allowed_addresses,
            allowed_move_call_targets,
        }
    }
}

impl From<String> for SubmitSponsorTransactionPayload {
    fn from(signature: String) -> Self {
        SubmitSponsorTransactionPayload { signature }
    }
}
