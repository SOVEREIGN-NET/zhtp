//! End-to-End Recovery Tests
//!
//! Tests the full recovery flow: CLI → API → Blockchain

use std::sync::Arc;
use tokio::sync::RwLock;
use lib_identity::{IdentityManager, economics::EconomicModel};
use lib_protocols::types::{ZhtpRequest, ZhtpMethod, ZhtpHeaders, ZhtpStatus};
use lib_protocols::zhtp::ZhtpRequestHandler;
use zhtp::api::handlers::identity::IdentityHandler;

#[tokio::test]
async fn test_e2e_identity_creation_and_recovery() {
    // Setup
    let identity_manager = Arc::new(RwLock::new(IdentityManager::new()));
    let economic_model = Arc::new(RwLock::new(EconomicModel::new()));
    let handler = IdentityHandler::new(identity_manager.clone(), economic_model.clone());

    // Step 1: Create a new citizen identity via API
    let create_request_data = serde_json::json!({
        "display_name": "Test E2E User",
        "identity_type": "human",
        "recovery_options": [],
        "password": "SecurePassword123"
    });

    let create_request = ZhtpRequest {
        method: ZhtpMethod::Post,
        uri: "/api/v1/identity/create".to_string(),
        version: "ZHTP/1.0".to_string(),
        headers: ZhtpHeaders::new(),
        body: serde_json::to_vec(&create_request_data).unwrap(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        requester: None,
        auth_proof: None,
    };

    let create_response = handler.handle_request(create_request).await.unwrap();
    assert_eq!(create_response.status, ZhtpStatus::Ok);

    // Parse creation response to get seed phrases
    let create_result: serde_json::Value = serde_json::from_slice(&create_response.body).unwrap();
    let citizenship = create_result.get("citizenship_result").unwrap();
    let seed_phrases = citizenship.get("wallet_seed_phrases").unwrap();

    let primary_seeds = seed_phrases.get("primary_wallet_seeds").unwrap()
        .get("words").unwrap().as_array().unwrap()
        .iter().map(|v| v.as_str().unwrap().to_string()).collect::<Vec<_>>();
    let ubi_seeds = seed_phrases.get("ubi_wallet_seeds").unwrap()
        .get("words").unwrap().as_array().unwrap()
        .iter().map(|v| v.as_str().unwrap().to_string()).collect::<Vec<_>>();
    let savings_seeds = seed_phrases.get("savings_wallet_seeds").unwrap()
        .get("words").unwrap().as_array().unwrap()
        .iter().map(|v| v.as_str().unwrap().to_string()).collect::<Vec<_>>();

    assert_eq!(primary_seeds.len(), 20);
    assert_eq!(ubi_seeds.len(), 20);
    assert_eq!(savings_seeds.len(), 20);

    // Step 2: Restore identity from seed phrases
    let restore_request_data = serde_json::json!({
        "primary_seed_phrase": primary_seeds,
        "ubi_seed_phrase": ubi_seeds,
        "savings_seed_phrase": savings_seeds,
        "password": "NewPassword456",
        "display_name": "Restored E2E User"
    });

    let restore_request = ZhtpRequest {
        method: ZhtpMethod::Post,
        uri: "/api/v1/identity/restore/seed".to_string(),
        version: "ZHTP/1.0".to_string(),
        headers: ZhtpHeaders::new(),
        body: serde_json::to_vec(&restore_request_data).unwrap(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        requester: None,
        auth_proof: None,
    };

    let restore_response = handler.handle_request(restore_request).await.unwrap();
    assert_eq!(restore_response.status, ZhtpStatus::Ok);

    let restore_result: serde_json::Value = serde_json::from_slice(&restore_response.body).unwrap();
    assert_eq!(restore_result.get("status").unwrap().as_str().unwrap(), "identity_restored");
    assert_eq!(restore_result.get("display_name").unwrap().as_str().unwrap(), "Restored E2E User");

    // Verify all 3 wallets were restored
    let wallets = restore_result.get("wallets").unwrap();
    assert!(!wallets.get("primary").unwrap().get("id").unwrap().as_str().unwrap().is_empty());
    assert!(!wallets.get("ubi").unwrap().get("id").unwrap().as_str().unwrap().is_empty());
    assert!(!wallets.get("savings").unwrap().get("id").unwrap().as_str().unwrap().is_empty());

    // Verify DAO and UBI registration
    assert!(restore_result.get("dao_voting_power").unwrap().as_u64().unwrap() > 0);
    assert!(restore_result.get("ubi_daily_amount").unwrap().as_u64().unwrap() > 0);
}

#[tokio::test]
async fn test_e2e_invalid_seed_phrase_rejection() {
    let identity_manager = Arc::new(RwLock::new(IdentityManager::new()));
    let economic_model = Arc::new(RwLock::new(EconomicModel::new()));
    let handler = IdentityHandler::new(identity_manager, economic_model);

    // Create invalid seed phrase (wrong word count)
    let invalid_seeds: Vec<String> = (0..15).map(|i| format!("word{}", i)).collect();

    let verify_request_data = serde_json::json!({
        "seed_phrase": invalid_seeds,
        "wallet_type": "primary"
    });

    let verify_request = ZhtpRequest {
        method: ZhtpMethod::Post,
        uri: "/api/v1/identity/seed/verify".to_string(),
        version: "ZHTP/1.0".to_string(),
        headers: ZhtpHeaders::new(),
        body: serde_json::to_vec(&verify_request_data).unwrap(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        requester: None,
        auth_proof: None,
    };

    let verify_response = handler.handle_request(verify_request).await.unwrap();
    assert_eq!(verify_response.status, ZhtpStatus::BadRequest);
}

#[tokio::test]
async fn test_e2e_deterministic_recovery() {
    let identity_manager1 = Arc::new(RwLock::new(IdentityManager::new()));
    let economic_model1 = Arc::new(RwLock::new(EconomicModel::new()));
    let handler1 = IdentityHandler::new(identity_manager1, economic_model1);

    let identity_manager2 = Arc::new(RwLock::new(IdentityManager::new()));
    let economic_model2 = Arc::new(RwLock::new(EconomicModel::new()));
    let handler2 = IdentityHandler::new(identity_manager2, economic_model2);

    // Create same seed phrases
    let primary_seeds: Vec<String> = (0..20).map(|i| format!("primary{:02}", i)).collect();
    let ubi_seeds: Vec<String> = (0..20).map(|i| format!("ubi{:02}", i)).collect();
    let savings_seeds: Vec<String> = (0..20).map(|i| format!("savings{:02}", i)).collect();

    // Restore in handler1
    let restore_request_data = serde_json::json!({
        "primary_seed_phrase": primary_seeds.clone(),
        "ubi_seed_phrase": ubi_seeds.clone(),
        "savings_seed_phrase": savings_seeds.clone(),
        "password": "TestPass123",
        "display_name": "User1"
    });

    let restore_request1 = ZhtpRequest {
        method: ZhtpMethod::Post,
        uri: "/api/v1/identity/restore/seed".to_string(),
        version: "ZHTP/1.0".to_string(),
        headers: ZhtpHeaders::new(),
        body: serde_json::to_vec(&restore_request_data).unwrap(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        requester: None,
        auth_proof: None,
    };

    let response1 = handler1.handle_request(restore_request1).await.unwrap();
    assert_eq!(response1.status, ZhtpStatus::Ok);

    // Restore same seeds in handler2
    let restore_request2 = ZhtpRequest {
        method: ZhtpMethod::Post,
        uri: "/api/v1/identity/restore/seed".to_string(),
        version: "ZHTP/1.0".to_string(),
        headers: ZhtpHeaders::new(),
        body: serde_json::to_vec(&restore_request_data).unwrap(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        requester: None,
        auth_proof: None,
    };

    let response2 = handler2.handle_request(restore_request2).await.unwrap();
    assert_eq!(response2.status, ZhtpStatus::Ok);

    // Parse both responses
    let result1: serde_json::Value = serde_json::from_slice(&response1.body).unwrap();
    let result2: serde_json::Value = serde_json::from_slice(&response2.body).unwrap();

    // Verify same identity IDs (deterministic)
    assert_eq!(
        result1.get("identity_id").unwrap().as_str().unwrap(),
        result2.get("identity_id").unwrap().as_str().unwrap()
    );

    // Verify same wallet IDs (deterministic)
    let wallets1 = result1.get("wallets").unwrap();
    let wallets2 = result2.get("wallets").unwrap();

    assert_eq!(
        wallets1.get("primary").unwrap().get("id").unwrap().as_str().unwrap(),
        wallets2.get("primary").unwrap().get("id").unwrap().as_str().unwrap()
    );
    assert_eq!(
        wallets1.get("ubi").unwrap().get("id").unwrap().as_str().unwrap(),
        wallets2.get("ubi").unwrap().get("id").unwrap().as_str().unwrap()
    );
    assert_eq!(
        wallets1.get("savings").unwrap().get("id").unwrap().as_str().unwrap(),
        wallets2.get("savings").unwrap().get("id").unwrap().as_str().unwrap()
    );
}

#[tokio::test]
async fn test_e2e_concurrent_recoveries() {
    use futures::future::join_all;

    let mut handles = Vec::new();

    // Launch 5 concurrent recovery operations
    for i in 0..5 {
        let handle: tokio::task::JoinHandle<Result<lib_protocols::types::ZhtpResponse, anyhow::Error>> = tokio::spawn(async move {
            let identity_manager = Arc::new(RwLock::new(IdentityManager::new()));
            let economic_model = Arc::new(RwLock::new(EconomicModel::new()));
            let handler = IdentityHandler::new(identity_manager, economic_model);

            let primary_seeds: Vec<String> = (0..20).map(|j| format!("p{}_{:02}", i, j)).collect();
            let ubi_seeds: Vec<String> = (0..20).map(|j| format!("u{}_{:02}", i, j)).collect();
            let savings_seeds: Vec<String> = (0..20).map(|j| format!("s{}_{:02}", i, j)).collect();

            let restore_request_data = serde_json::json!({
                "primary_seed_phrase": primary_seeds,
                "ubi_seed_phrase": ubi_seeds,
                "savings_seed_phrase": savings_seeds,
                "password": format!("Pass{}", i),
                "display_name": format!("Concurrent User {}", i)
            });

            let restore_request = ZhtpRequest {
                method: ZhtpMethod::Post,
                uri: "/api/v1/identity/restore/seed".to_string(),
                version: "ZHTP/1.0".to_string(),
                headers: ZhtpHeaders::new(),
                body: serde_json::to_vec(&restore_request_data).unwrap(),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                requester: None,
                auth_proof: None,
            };

            handler.handle_request(restore_request).await
        });

        handles.push(handle);
    }

    // Wait for all to complete
    let results = join_all(handles).await;

    // All should succeed
    for (i, result) in results.iter().enumerate() {
        assert!(result.is_ok(), "Concurrent recovery {} failed", i);
        let response = result.as_ref().unwrap().as_ref().unwrap();
        assert_eq!(response.status, ZhtpStatus::Ok, "Concurrent recovery {} returned wrong status", i);
    }

    // Verify all have unique identity IDs
    let mut identity_ids = std::collections::HashSet::new();
    for result in results {
        let response = result.unwrap().unwrap();
        let data: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        let id = data.get("identity_id").unwrap().as_str().unwrap();
        assert!(identity_ids.insert(id.to_string()), "Duplicate identity ID found");
    }

    assert_eq!(identity_ids.len(), 5, "Should have 5 unique identity IDs");
}
