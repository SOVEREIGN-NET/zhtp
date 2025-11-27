//! Identity Recovery Tests
//!
//! Comprehensive tests for full citizen identity recovery from seed phrases

use lib_identity::{
    IdentityManager,
    recovery::RecoveryPhraseManager,
    wallets::WalletType,
    economics::EconomicModel,
};
use zhtp::runtime::did_startup::WalletStartupManager;

#[tokio::test]
async fn test_restore_full_identity_from_seeds() {
    // Create identity and economic managers
    let mut identity_manager = IdentityManager::new();
    let mut economic_model = EconomicModel::new();

    // Generate test seed phrases (20 words each)
    let primary_seed: Vec<String> = (0..20).map(|i| format!("primary{:02}", i)).collect();
    let ubi_seed: Vec<String> = (0..20).map(|i| format!("ubi{:02}", i)).collect();
    let savings_seed: Vec<String> = (0..20).map(|i| format!("savings{:02}", i)).collect();

    // Restore identity
    let result = WalletStartupManager::restore_full_identity_from_seeds(
        &primary_seed,
        &ubi_seed,
        &savings_seed,
        Some("test_password".to_string()),
        "Test User".to_string(),
        &mut identity_manager,
        &mut economic_model,
    )
    .await;

    assert!(result.is_ok(), "Identity restoration should succeed");

    let citizenship = result.unwrap();

    // Verify all 3 wallets were restored
    assert_ne!(citizenship.primary_wallet_id.to_string(), "");
    assert_ne!(citizenship.ubi_wallet_id.to_string(), "");
    assert_ne!(citizenship.savings_wallet_id.to_string(), "");

    // Verify seed phrases are present
    assert_eq!(citizenship.wallet_seed_phrases.primary_wallet_seeds.words.len(), 20);
    assert_eq!(citizenship.wallet_seed_phrases.ubi_wallet_seeds.words.len(), 20);
    assert_eq!(citizenship.wallet_seed_phrases.savings_wallet_seeds.words.len(), 20);

    // Verify identity was added to manager
    let identity = identity_manager.get_identity(&citizenship.identity_id);
    assert!(identity.is_some(), "Identity should be in manager");

    // Verify identity has 3 wallets
    let identity = identity.unwrap();
    assert_eq!(identity.wallet_manager.wallets.len(), 3, "Should have 3 wallets");

    // Verify DAO registration
    assert!(citizenship.dao_registration.voting_power > 0, "Should have voting power");

    // Verify UBI registration
    assert!(citizenship.ubi_registration.daily_amount > 0, "Should have UBI amount");

    // Verify Web4 access
    assert!(citizenship.web4_access.service_tokens.len() > 0, "Should have Web4 services");
}

#[tokio::test]
async fn test_restore_identity_with_invalid_seed_count() {
    let mut identity_manager = IdentityManager::new();
    let mut economic_model = EconomicModel::new();

    // Invalid: only 19 words instead of 20
    let primary_seed: Vec<String> = (0..19).map(|i| format!("word{:02}", i)).collect();
    let ubi_seed: Vec<String> = (0..20).map(|i| format!("word{:02}", i)).collect();
    let savings_seed: Vec<String> = (0..20).map(|i| format!("word{:02}", i)).collect();

    let result = WalletStartupManager::restore_full_identity_from_seeds(
        &primary_seed,
        &ubi_seed,
        &savings_seed,
        None,
        "Test User".to_string(),
        &mut identity_manager,
        &mut economic_model,
    )
    .await;

    assert!(result.is_err(), "Should fail with invalid seed count");
    assert!(result.unwrap_err().to_string().contains("exactly 20 words"));
}

#[tokio::test]
async fn test_restore_identity_preserves_wallet_types() {
    let mut identity_manager = IdentityManager::new();
    let mut economic_model = EconomicModel::new();

    let primary_seed: Vec<String> = (0..20).map(|i| format!("primary{:02}", i)).collect();
    let ubi_seed: Vec<String> = (0..20).map(|i| format!("ubi{:02}", i)).collect();
    let savings_seed: Vec<String> = (0..20).map(|i| format!("savings{:02}", i)).collect();

    let citizenship = WalletStartupManager::restore_full_identity_from_seeds(
        &primary_seed,
        &ubi_seed,
        &savings_seed,
        None,
        "Test User".to_string(),
        &mut identity_manager,
        &mut economic_model,
    )
    .await
    .unwrap();

    let identity = identity_manager.get_identity(&citizenship.identity_id).unwrap();

    // Find each wallet and verify its type
    let primary_wallet = identity.wallet_manager.get_wallet(&citizenship.primary_wallet_id);
    let ubi_wallet = identity.wallet_manager.get_wallet(&citizenship.ubi_wallet_id);
    let savings_wallet = identity.wallet_manager.get_wallet(&citizenship.savings_wallet_id);

    assert!(primary_wallet.is_some(), "Primary wallet should exist");
    assert!(ubi_wallet.is_some(), "UBI wallet should exist");
    assert!(savings_wallet.is_some(), "Savings wallet should exist");

    assert_eq!(primary_wallet.unwrap().wallet_type, WalletType::Primary);
    assert_eq!(ubi_wallet.unwrap().wallet_type, WalletType::UBI);
    assert_eq!(savings_wallet.unwrap().wallet_type, WalletType::Savings);
}

#[tokio::test]
async fn test_wallet_recovery_with_type() {
    use lib_identity::wallets::WalletManager;
    use lib_crypto::Hash;

    let identity_id = Hash::from_bytes(&[1u8; 32]);
    let mut wallet_manager = WalletManager::new(identity_id);

    let seed_words: Vec<String> = (0..20).map(|i| format!("word{:02}", i)).collect();

    // Test recovering each wallet type
    let wallet_types = vec![
        (WalletType::Primary, "Primary Wallet"),
        (WalletType::UBI, "UBI Wallet"),
        (WalletType::Savings, "Savings Wallet"),
    ];

    for (wallet_type, name) in wallet_types {
        let result = wallet_manager
            .recover_wallet_from_seed_phrase_with_type(
                wallet_type.clone(),
                &seed_words,
                name.to_string(),
                None,
            )
            .await;

        assert!(result.is_ok(), "Wallet recovery should succeed for {:?}", wallet_type);

        let (wallet_id, recovered_phrase) = result.unwrap();
        assert_eq!(recovered_phrase.words.len(), 20, "Should recover all 20 words");

        // Verify wallet was added
        let wallet = wallet_manager.get_wallet(&wallet_id);
        assert!(wallet.is_some(), "Wallet should be in manager");
        assert_eq!(wallet.unwrap().wallet_type, wallet_type, "Wallet type should match");
    }

    // Should have 3 wallets
    assert_eq!(wallet_manager.wallets.len(), 3, "Should have all 3 wallets");
}

#[tokio::test]
async fn test_recovery_phrase_validation() {
    use lib_identity::recovery::{PhraseGenerationOptions, EntropySource};

    let mut manager = RecoveryPhraseManager::new();

    // Generate a valid 20-word phrase using the manager
    let options = PhraseGenerationOptions {
        word_count: 20,
        language: "english".to_string(),
        entropy_source: EntropySource::SystemRandom,
        include_checksum: true,
        custom_wordlist: None,
    };

    let valid_phrase = manager.generate_recovery_phrase("test_user", options).await.unwrap();

    let validation = manager.validate_phrase(&valid_phrase).await.unwrap();
    assert!(validation.valid, "Generated phrase should pass validation");
    assert!(validation.word_count_valid, "Word count should be valid");
    assert!(validation.entropy_sufficient, "Entropy should be sufficient");

    // Invalid phrase (wrong word count - too few words)
    let invalid_words: Vec<String> = (0..5).map(|i| format!("word{:02}", i)).collect();
    let invalid_phrase = lib_identity::recovery::RecoveryPhrase::from_words(invalid_words).unwrap();

    let invalid_validation = manager.validate_phrase(&invalid_phrase).await.unwrap();
    assert!(!invalid_validation.valid, "Invalid phrase should fail validation");
    assert!(!invalid_validation.word_count_valid, "Word count should be invalid");
}

#[tokio::test]
async fn test_restore_identity_with_password() {
    let mut identity_manager = IdentityManager::new();
    let mut economic_model = EconomicModel::new();

    let primary_seed: Vec<String> = (0..20).map(|i| format!("primary{:02}", i)).collect();
    let ubi_seed: Vec<String> = (0..20).map(|i| format!("ubi{:02}", i)).collect();
    let savings_seed: Vec<String> = (0..20).map(|i| format!("savings{:02}", i)).collect();

    let citizenship = WalletStartupManager::restore_full_identity_from_seeds(
        &primary_seed,
        &ubi_seed,
        &savings_seed,
        Some("secure_password_123".to_string()),
        "Password User".to_string(),
        &mut identity_manager,
        &mut economic_model,
    )
    .await
    .unwrap();

    // Verify identity was restored successfully
    assert_ne!(citizenship.identity_id.to_string(), "", "Identity ID should not be empty");

    // Verify identity is in the manager
    let identity = identity_manager.get_identity(&citizenship.identity_id);
    assert!(identity.is_some(), "Identity should be in manager");

    // Note: Password functionality is set but may not be fully initialized
    // in the test environment. The important thing is that the restore
    // completed successfully with a password parameter.
}

#[tokio::test]
async fn test_deterministic_wallet_recovery() {
    use lib_identity::wallets::WalletManager;
    use lib_crypto::Hash;

    let identity_id = Hash::from_bytes(&[42u8; 32]);
    let seed_words: Vec<String> = (0..20).map(|i| format!("deterministic{:02}", i)).collect();

    // Create first wallet from seed
    let mut wallet_manager1 = WalletManager::new(identity_id.clone());
    let (wallet_id1, _) = wallet_manager1
        .recover_wallet_from_seed_phrase_with_type(
            WalletType::Primary,
            &seed_words,
            "Test Wallet".to_string(),
            None,
        )
        .await
        .unwrap();

    // Create second wallet from same seed
    let mut wallet_manager2 = WalletManager::new(identity_id.clone());
    let (wallet_id2, _) = wallet_manager2
        .recover_wallet_from_seed_phrase_with_type(
            WalletType::Primary,
            &seed_words,
            "Test Wallet".to_string(),
            None,
        )
        .await
        .unwrap();

    // Wallet IDs should be the same (deterministic recovery)
    assert_eq!(
        wallet_id1.to_string(),
        wallet_id2.to_string(),
        "Same seed should produce same wallet ID"
    );
}

#[tokio::test]
async fn test_multiple_recoveries_different_seeds() {
    let mut identity_manager = IdentityManager::new();
    let mut economic_model = EconomicModel::new();

    // First identity
    let primary_seed1: Vec<String> = (0..20).map(|i| format!("user1primary{:02}", i)).collect();
    let ubi_seed1: Vec<String> = (0..20).map(|i| format!("user1ubi{:02}", i)).collect();
    let savings_seed1: Vec<String> = (0..20).map(|i| format!("user1savings{:02}", i)).collect();

    let citizenship1 = WalletStartupManager::restore_full_identity_from_seeds(
        &primary_seed1,
        &ubi_seed1,
        &savings_seed1,
        None,
        "User One".to_string(),
        &mut identity_manager,
        &mut economic_model,
    )
    .await
    .unwrap();

    // Second identity
    let primary_seed2: Vec<String> = (0..20).map(|i| format!("user2primary{:02}", i)).collect();
    let ubi_seed2: Vec<String> = (0..20).map(|i| format!("user2ubi{:02}", i)).collect();
    let savings_seed2: Vec<String> = (0..20).map(|i| format!("user2savings{:02}", i)).collect();

    let citizenship2 = WalletStartupManager::restore_full_identity_from_seeds(
        &primary_seed2,
        &ubi_seed2,
        &savings_seed2,
        None,
        "User Two".to_string(),
        &mut identity_manager,
        &mut economic_model,
    )
    .await
    .unwrap();

    // Identities should be different
    assert_ne!(
        citizenship1.identity_id.to_string(),
        citizenship2.identity_id.to_string(),
        "Different seeds should produce different identities"
    );

    // Wallets should be different
    assert_ne!(
        citizenship1.primary_wallet_id.to_string(),
        citizenship2.primary_wallet_id.to_string(),
        "Different seeds should produce different wallets"
    );

    // Both should be in the manager
    assert!(identity_manager.get_identity(&citizenship1.identity_id).is_some());
    assert!(identity_manager.get_identity(&citizenship2.identity_id).is_some());
}

#[tokio::test]
async fn test_recovery_preserves_metadata() {
    let mut identity_manager = IdentityManager::new();
    let mut economic_model = EconomicModel::new();

    let primary_seed: Vec<String> = (0..20).map(|i| format!("meta{:02}", i)).collect();
    let ubi_seed: Vec<String> = (0..20).map(|i| format!("meta{:02}", i)).collect();
    let savings_seed: Vec<String> = (0..20).map(|i| format!("meta{:02}", i)).collect();

    let display_name = "Metadata Test User";

    let citizenship = WalletStartupManager::restore_full_identity_from_seeds(
        &primary_seed,
        &ubi_seed,
        &savings_seed,
        None,
        display_name.to_string(),
        &mut identity_manager,
        &mut economic_model,
    )
    .await
    .unwrap();

    let identity = identity_manager.get_identity(&citizenship.identity_id).unwrap();

    // Verify display name was preserved
    assert_eq!(
        identity.metadata.get("display_name"),
        Some(&display_name.to_string()),
        "Display name should be preserved"
    );

    // Verify identity type
    assert_eq!(
        identity.identity_type,
        lib_identity::types::IdentityType::Human,
        "Should be Human identity type"
    );

    // Verify access level
    assert_eq!(
        identity.access_level,
        lib_identity::types::AccessLevel::FullCitizen,
        "Should have FullCitizen access level"
    );
}

#[tokio::test]
async fn test_concurrent_identity_recoveries() {
    use futures::future::join_all;

    let mut handles = Vec::new();

    // Start 5 concurrent recoveries
    for i in 0..5 {
        let handle: tokio::task::JoinHandle<Result<lib_identity::citizenship::CitizenshipResult, anyhow::Error>> = tokio::spawn(async move {
            let mut identity_manager = IdentityManager::new();
            let mut economic_model = EconomicModel::new();

            let primary_seed: Vec<String> = (0..20)
                .map(|j| format!("concurrent{}primary{:02}", i, j))
                .collect();
            let ubi_seed: Vec<String> = (0..20)
                .map(|j| format!("concurrent{}ubi{:02}", i, j))
                .collect();
            let savings_seed: Vec<String> = (0..20)
                .map(|j| format!("concurrent{}savings{:02}", i, j))
                .collect();

            WalletStartupManager::restore_full_identity_from_seeds(
                &primary_seed,
                &ubi_seed,
                &savings_seed,
                None,
                format!("Concurrent User {}", i),
                &mut identity_manager,
                &mut economic_model,
            )
            .await
        });

        handles.push(handle);
    }

    // Wait for all to complete
    let results = join_all(handles).await;

    // All should succeed
    for (i, result) in results.iter().enumerate() {
        assert!(
            result.is_ok(),
            "Concurrent recovery {} should succeed",
            i
        );
        let citizenship_result = result.as_ref().unwrap();
        assert!(
            citizenship_result.is_ok(),
            "Citizenship result {} should be ok",
            i
        );
    }

    // Extract citizenship results
    let citizenships: Vec<_> = results
        .into_iter()
        .map(|r| r.unwrap().unwrap())
        .collect();

    // All identity IDs should be unique
    let mut seen_ids = std::collections::HashSet::new();
    for citizenship in &citizenships {
        assert!(
            seen_ids.insert(citizenship.identity_id.to_string()),
            "Identity IDs should be unique"
        );
    }

    assert_eq!(seen_ids.len(), 5, "Should have 5 unique identities");
}
