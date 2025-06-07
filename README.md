# Squad Connect

A Rust SDK for Sui blockchain integration with zkLogin authentication, transaction signing, and sponsor transaction support.

## Features

- 🔐 **zkLogin Authentication** - Google OAuth integration with zero-knowledge proofs
- 📱 **Transaction Management** - Sign and execute transactions on Sui blockchain
- 💰 **Sponsor Transactions** - Support for gasless transactions via sponsors
- 🔄 **Format Conversion** - Automatic camelCase to snake_case conversion for API responses
- 🛡️ **Error Handling** - Comprehensive error handling with detailed error messages
- 🌐 **Multi-Network** - Support for Devnet, Testnet, and Mainnet

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
squad_connect = "0.0.2"
sui_sdk = { git = "https://github.com/mystenlabs/sui", package = "sui-sdk"}
fastcrypto_zkp = "0.1.3"
tokio = "1.45.0"
serde = "1.0.219"
```

## Quick Start

### 1. Initialize Squad Connect

```rust
use squad_connect::client::squard_connect::SquardConnect;
use squad_connect::service::dtos::Network;
use sui_sdk::SuiClientBuilder;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create Sui client
    let sui_client = SuiClientBuilder::default().build_testnet().await?;
    
    // Initialize Squad Connect
    let mut squad_connect = SquardConnect::new(
        sui_client,
        "your-google-client-id".to_string(),
        Network::Testnet,
        "your-api-key".to_string(),
    );

    Ok(())
}
```

### 2. zkLogin Authentication Flow

```rust
use std::path::PathBuf;

async fn zklogin_flow() -> Result<(), Box<dyn std::error::Error>> {
    let mut squad_connect = /* ... initialize as above ... */;
    
    // Step 1: Create zkLogin payload and get OAuth URL
    let keystore_path = PathBuf::from("./keystore");
    squad_connect.create_zkp_payload(keystore_path.clone()).await?;
    
    let oauth_url = squad_connect.get_url(
        "http://localhost:3000/callback".to_string(),
        Some("custom_state".to_string())
    ).await?;
    
    println!("Visit this URL to authenticate: {}", oauth_url);
    
    // Step 2: Extract JWT from callback (after user authenticates)
    let callback_url = "http://localhost:3000/callback#id_token=eyJ...&state=custom_state";
    squad_connect.set_jwt(
        squad_connect.services.extract_jwt_from_callback(callback_url)?
    );
    
    // Step 3: Generate ZK proof and get account
    let zk_login_inputs = squad_connect.recover_seed_address().await?;
    let account = squad_connect.get_address().await?;
    
    println!("Account address: {}", account.address);
    println!("Public key: {}", account.public_key);
    
    Ok(())
}
```

### 3. Sign and Execute Transaction

```rust
use sui_sdk::types::{
    base_types::SuiAddress,
    transaction::TransactionData,
};
use std::str::FromStr;

async fn sign_transaction_example() -> Result<(), Box<dyn std::error::Error>> {
    let squad_connect = /* ... initialize and authenticate ... */;
    
    // Get account and ZK login inputs
    let account = squad_connect.get_address().await?;
    let zk_login_inputs = squad_connect.recover_seed_address().await?;
    let (_, _, max_epoch) = squad_connect.get_zk_proof_params();
    
    // Create transaction data (example - transfer SUI)
    let transaction_data: TransactionData = /* ... build your transaction ... */;
    
    // Get signer address
    let signer = SuiAddress::from_str(&account.public_key)?;
    
    // Sign transaction
    let keystore_path = PathBuf::from("./keystore");
    let signed_transaction = squad_connect.sign_transaction(
        transaction_data,
        signer,
        zk_login_inputs,
        max_epoch,
        keystore_path,
    ).await?;
    
    println!("Transaction signed successfully!");
    
    Ok(())
}
```

### 4. Sponsor Transaction (Gasless)

```rust
use sui_sdk::types::base_types::SuiAddress;

async fn sponsor_transaction_example() -> Result<(), Box<dyn std::error::Error>> {
    let mut squad_connect = /* ... initialize and authenticate ... */;
    
    // Build your transaction data
    let transaction_data: TransactionData = /* ... */;
    let sender = SuiAddress::from_str("0x123...")?;
    
    // Configure allowed addresses and move call targets
    let allowed_addresses = vec![
        "0x456...".to_string(),
        "0x789...".to_string(),
    ];
    let allowed_move_call_targets = vec![
        "0xabc::module::function".to_string(),
    ];
    
    // Submit sponsor transaction
    let result_digest = squad_connect.sponsor_transaction(
        transaction_data,
        sender,
        allowed_addresses,
        allowed_move_call_targets,
    ).await?;
    
    println!("Sponsor transaction digest: {}", result_digest);
    
    Ok(())
}
```

## Advanced Usage

### Error Handling

```rust
use squad_connect::service::types::ServiceError;

async fn handle_errors() {
    match squad_connect.get_address().await {
        Ok(account) => println!("Success: {}", account.address),
        Err(ServiceError::Network(msg)) => {
            eprintln!("Network error: {}", msg);
        }
        Err(ServiceError::JwtFormat(msg)) => {
            eprintln!("JWT format error: {}", msg);
        }
        Err(ServiceError::JwtExtraction(msg)) => {
            eprintln!("JWT extraction error: {}", msg);
        }
        Err(e) => eprintln!("Other error: {}", e),
    }
}
```

### State Management

```rust
// Extract state from OAuth callback
let state: Option<String> = squad_connect.extract_state_from_callback(callback_url)?;
if let Some(custom_state) = state {
    println!("Received state: {}", custom_state);
}

// Manage ZK proof parameters
let (randomness, public_key, max_epoch) = squad_connect.get_zk_proof_params();
squad_connect.set_zk_proof_params(randomness, public_key, max_epoch);
```

### Multi-Network Support

```rust
use squad_connect::service::dtos::Network;

// Testnet
let testnet_client = SquardConnect::new(
    sui_client,
    client_id,
    Network::Testnet,
    api_key,
);

// Mainnet
let mainnet_client = SquardConnect::new(
    sui_client,
    client_id,
    Network::Mainnet,
    api_key,
);

// Devnet
let devnet_client = SquardConnect::new(
    sui_client,
    client_id,
    Network::Devnet,
    api_key,
);
```

## Configuration

### Environment Variables

```bash
export GOOGLE_CLIENT_ID="your-google-oauth-client-id"
export ENOKI_API_KEY="your-enoki-api-key"
export NETWORK="testnet"  # or "mainnet", "devnet"
```

### Google OAuth Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Enable Google+ API
4. Create OAuth 2.0 credentials
5. Add your redirect URIs
6. Copy the Client ID

## API Reference

### SquardConnect Methods

#### Authentication
- `create_zkp_payload(path: PathBuf) -> Result<()>` - Initialize zkLogin parameters
- `get_url<T>(redirect_url: String, state: Option<T>) -> Result<String>` - Get OAuth URL
- `set_jwt(jwt: String)` - Set JWT token from OAuth callback
- `recover_seed_address() -> Result<ZkLoginInputs>` - Generate ZK proof
- `get_address() -> Result<AccountResponse>` - Get account information

#### Transaction Management
- `sign_transaction(...) -> Result<Transaction>` - Sign transaction with zkLogin
- `sponsor_transaction(...) -> Result<String>` - Submit gasless transaction

#### Utilities
- `extract_state_from_callback<T>(url: &str) -> Result<Option<T>>` - Extract OAuth state
- `get_zk_proof_params() -> (String, String, u64)` - Get ZK proof parameters
- `set_zk_proof_params(...)` - Set ZK proof parameters

## Error Types

```rust
pub enum ServiceError {
    Service(String),        // General service errors
    Network(String),        // Network/HTTP errors  
    InvalidResponse(String), // Invalid API responses
    InvalidProof(String),   // ZK proof validation errors
    JwtFormat(String),      // JWT parsing errors
    JwtExtraction(String),  // JWT extraction from URLs
}
```

## Examples Repository

For more examples, check out:
- [Sui Squad Bot Handlers](https://github.com/Singularity-Shift/sui_squad/blob/main/sui-squad-bot/src/bot_manage/handlers.rs)
- [Sui Squad Server Fund Handler](https://github.com/Singularity-Shift/sui_squad/blob/main/sui-squad-server/src/fund/handler.rs)

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- 📖 [Documentation](https://docs.sui.io/)
- 💬 [Discord Community](https://discord.gg/sui)
- 🐛 [Issue Tracker](https://github.com/your-repo/squad-connect/issues)
