use std::fmt;

#[derive(Debug)]
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
pub struct AddressResponse {
    pub salt: String,
    pub address: String,
    pub public_key: String,
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
pub struct ZKPResponse {
    pub address_seed: String,
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
