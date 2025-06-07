//! # Squad Connect Basic Usage Example
//!
//! This example demonstrates the complete flow of using Squad Connect for zkLogin authentication
//! and transaction management on the Sui blockchain.
//!
//! ## Prerequisites
//! 1. Set up Google OAuth credentials
//! 2. Get an Enoki API key
//! 3. Set environment variables:
//!    - GOOGLE_CLIENT_ID
//!    - ENOKI_API_KEY
//!
//! ## Usage
//! ```bash
//! cargo run --example basic_usage
//! ```

use squad_connect::{
    client::squad_connect::SquadConnect,
    service::{dtos::Network, types::ServiceError},
};
use std::{env, path::PathBuf};
use sui_sdk::SuiClientBuilder;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration from environment
    let google_client_id =
        env::var("GOOGLE_CLIENT_ID").expect("GOOGLE_CLIENT_ID environment variable not set");
    let enoki_api_key =
        env::var("ENOKI_API_KEY").expect("ENOKI_API_KEY environment variable not set");

    println!("🚀 Starting Squad Connect Example");

    // Initialize Sui client for testnet
    println!("📡 Connecting to Sui testnet...");
    let sui_client = SuiClientBuilder::default().build_testnet().await?;
    println!("✅ Connected to Sui testnet");

    // Create Squad Connect instance
    let mut squad_connect = SquadConnect::new(
        sui_client,
        google_client_id,
        Network::Testnet,
        enoki_api_key,
    );

    // Step 1: Initialize zkLogin parameters
    println!("\n🔑 Setting up zkLogin parameters...");
    let keystore_path = PathBuf::from("./keystore");

    match squad_connect
        .create_zkp_payload(keystore_path.clone())
        .await
    {
        Ok(_) => println!("✅ zkLogin parameters initialized"),
        Err(e) => {
            eprintln!("❌ Failed to initialize zkLogin: {}", e);
            return Err(e.into());
        }
    }

    // Step 2: Generate OAuth URL
    println!("\n🌐 Generating OAuth URL...");
    let redirect_url = "http://localhost:3000/callback".to_string();
    let state = Some("example_state_12345".to_string());

    let oauth_url = match squad_connect.get_url(redirect_url, state).await {
        Ok(url) => {
            println!("✅ OAuth URL generated");
            println!("🔗 Visit this URL to authenticate:");
            println!("   {}", url);
            url
        }
        Err(e) => {
            eprintln!("❌ Failed to generate OAuth URL: {}", e);
            return Err(e.into());
        }
    };

    // In a real application, you would:
    // 1. Open the OAuth URL in a browser
    // 2. User completes Google authentication
    // 3. Handle the callback with the JWT token

    println!("\n⏳ Waiting for user authentication...");
    println!("💡 In a real app, you would:");
    println!("   1. Open the OAuth URL in a browser");
    println!("   2. Handle the callback to extract JWT");
    println!("   3. Continue with the flow below");

    // Example callback URL (in practice, this comes from your web server)
    let example_callback = r#"
    After user authentication, you'll receive a callback like:
    http://localhost:3000/callback#id_token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...&state=example_state_12345
    "#;
    println!("{}", example_callback);

    // Demonstrate error handling
    demonstrate_error_handling(&squad_connect).await;

    // Show utility functions
    demonstrate_utilities(&squad_connect);

    println!("\n🎉 Example completed successfully!");
    println!("📚 Check the README.md for more detailed examples");

    Ok(())
}

/// Demonstrates proper error handling with Squad Connect
async fn demonstrate_error_handling(squad_connect: &SquadConnect) {
    println!("\n🛡️  Demonstrating error handling...");

    // Example of handling different error types
    match squad_connect.get_address().await {
        Ok(account) => {
            println!("✅ Account retrieved: {}", account.address);
        }
        Err(ServiceError::Network(msg)) => {
            println!("🌐 Network error (expected): {}", msg);
        }
        Err(ServiceError::JwtFormat(msg)) => {
            println!("📄 JWT format error (expected): {}", msg);
        }
        Err(ServiceError::JwtExtraction(msg)) => {
            println!("🔍 JWT extraction error (expected): {}", msg);
        }
        Err(ServiceError::InvalidResponse(msg)) => {
            println!("❌ Invalid response error (expected): {}", msg);
        }
        Err(e) => {
            println!("⚠️  Other error (expected): {}", e);
        }
    }
}

/// Demonstrates utility functions
fn demonstrate_utilities(squad_connect: &SquadConnect) {
    println!("\n🔧 Demonstrating utility functions...");

    // Get ZK proof parameters
    let (randomness, public_key, max_epoch) = squad_connect.get_zk_proof_params();
    println!("📊 ZK Proof Parameters:");
    println!("   Randomness: {} chars", randomness.len());
    println!("   Public Key: {} chars", public_key.len());
    println!("   Max Epoch: {}", max_epoch);

    // Example callback URL parsing
    let example_callback = "http://localhost:3000/callback#id_token=test_token&state=example_state";
    match squad_connect.extract_state_from_callback::<String>(example_callback) {
        Ok(Some(state)) => println!("📤 Extracted state: {}", state),
        Ok(None) => println!("📤 No state found in callback"),
        Err(e) => println!("❌ Error extracting state: {}", e),
    }
}

/// Complete zkLogin flow example (commented out since it requires user interaction)
#[allow(dead_code)]
async fn complete_zklogin_flow() -> Result<(), Box<dyn std::error::Error>> {
    // This function shows what a complete flow looks like
    // It's commented out since it requires actual user interaction

    /*
    let mut squad_connect = /* initialize as above */;

    // 1. Setup zkLogin
    squad_connect.create_zkp_payload(PathBuf::from("./keystore")).await?;

    // 2. Get OAuth URL
    let oauth_url = squad_connect.get_url(
        "http://localhost:3000/callback".to_string(),
        Some("my_state".to_string())
    ).await?;

    // 3. User visits oauth_url and authenticates
    // 4. Your server receives callback with JWT

    // 5. Extract JWT and set it
    let callback_url = "http://localhost:3000/callback#id_token=...";
    let jwt = squad_connect.extract_jwt_from_callback(callback_url)?;
    squad_connect.set_jwt(jwt);

    // 6. Generate ZK proof
    let zk_inputs = squad_connect.recover_seed_address().await?;

    // 7. Get account information
    let account = squad_connect.get_address().await?;
    println!("Account: {}", account.address);

    // 8. Sign transactions (if needed)
    // let signed_tx = squad_connect.sign_transaction(...).await?;

    // 9. Submit sponsor transactions (if needed)
    // let digest = squad_connect.sponsor_transaction(...).await?;
    */

    Ok(())
}
