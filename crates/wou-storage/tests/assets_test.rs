use wou_core::{AssetStatus, Collection, TokenMetadata, TokenType};
use wou_storage::WouStorage;

fn test_storage(name: &str) -> (WouStorage, tempfile::TempDir) {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let redb_path = temp_dir.path().join(name);
    let storage = WouStorage::new("redis://127.0.0.1:6379", redb_path.to_str().unwrap())
        .expect("Failed to initialize WouStorage");
    (storage, temp_dir)
}

fn meta(name: &str) -> TokenMetadata {
    TokenMetadata {
        name: name.to_string(),
        description: "desc".to_string(),
        image: "/img.webp".to_string(),
        attributes: vec![],
        collection: "genesis".to_string(),
    }
}

async fn seed(storage: &WouStorage) {
    storage
        .create_collection(Collection {
            id: "genesis".to_string(),
            name: "Cosmicrafts Genesis".to_string(),
            symbol: "GEN".to_string(),
            description: "".to_string(),
            image: "".to_string(),
            created_at: 0,
        })
        .await
        .unwrap();
    storage
        .register_token(TokenType {
            id: "genesis-001".to_string(),
            collection: "genesis".to_string(),
            metadata: meta("Riftcutter"),
            max_supply: 2,
            minted: 0,
            created_at: 0,
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn registry_rejects_duplicates_and_unknown_collections() {
    let (storage, _dir) = test_storage("assets_reg.redb");
    seed(&storage).await;
    let dup = storage
        .create_collection(Collection {
            id: "genesis".to_string(),
            name: "x".to_string(),
            symbol: "x".to_string(),
            description: "".to_string(),
            image: "".to_string(),
            created_at: 0,
        })
        .await;
    assert!(dup.is_err());
    let orphan = storage
        .register_token(TokenType {
            id: "zzz-001".to_string(),
            collection: "nope".to_string(),
            metadata: meta("Zzz"),
            max_supply: 10,
            minted: 0,
            created_at: 0,
        })
        .await;
    assert!(orphan.is_err());
    assert_eq!(storage.list_collections().await.unwrap().len(), 1);
    assert_eq!(storage.tokens_of_collection("genesis").await.unwrap().len(), 1);
}

#[tokio::test]
async fn claim_mints_serials_and_exhausts_supply() {
    let (storage, _dir) = test_storage("assets_claim.redb");
    seed(&storage).await;
    let a = storage.claim_token("genesis-001", "alice", "alice").await.unwrap();
    assert_eq!(a.id, "genesis-001#1");
    assert_eq!(a.serial, 1);
    assert_eq!(a.owner, "alice");
    assert_eq!(a.status, AssetStatus::Active);
    assert!(!a.metadata_digest.is_empty());
    let b = storage.claim_token("genesis-001", "bob", "bob").await.unwrap();
    assert_eq!(b.id, "genesis-001#2");
    assert!(storage.claim_token("genesis-001", "carol", "carol").await.is_err());
    assert_eq!(storage.get_token("genesis-001").await.unwrap().unwrap().minted, 2);
}

#[tokio::test]
async fn transfer_freeze_restore_with_events() {
    let (storage, _dir) = test_storage("assets_move.redb");
    seed(&storage).await;
    storage.claim_token("genesis-001", "alice", "alice").await.unwrap();
    // stranger cannot move it
    assert!(storage.transfer_asset("genesis-001#1", "mallory", "mallory", "mallory").await.is_err());
    // owner moves it
    let moved = storage.transfer_asset("genesis-001#1", "alice", "bob", "alice").await.unwrap();
    assert_eq!(moved.owner, "bob");
    // freeze blocks moves
    storage.set_asset_status("genesis-001#1", AssetStatus::Frozen, "producer").await.unwrap();
    assert!(storage.transfer_asset("genesis-001#1", "bob", "alice", "bob").await.is_err());
    // restore re-enables
    storage.set_asset_status("genesis-001#1", AssetStatus::Active, "producer").await.unwrap();
    assert!(storage.transfer_asset("genesis-001#1", "bob", "alice", "bob").await.is_ok());
    let mut kinds: Vec<String> = storage
        .asset_events("genesis-001#1")
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.kind)
        .collect();
    kinds.sort();
    assert_eq!(kinds, vec!["freeze", "mint", "restore", "transfer", "transfer"]);
}

#[tokio::test]
async fn marketplace_faucet_list_buy() {
    let (storage, _dir) = test_storage("assets_market.redb");
    seed(&storage).await;
    assert_eq!(storage.faucet_spiral("alice", 100).await.unwrap(), 100);
    assert_eq!(storage.faucet_spiral("bob", 30).await.unwrap(), 30);
    assert_eq!(storage.spiral_balance("carol").await.unwrap(), 0);
    storage.claim_token("genesis-001", "alice", "alice").await.unwrap();
    // non-owner cannot list
    assert!(storage.create_listing("genesis-001#1", "mallory", 50).await.is_err());
    let l = storage.create_listing("genesis-001#1", "alice", 50).await.unwrap();
    assert_eq!(l.status, "open");
    // listed instance refuses direct moves
    assert!(storage.transfer_asset("genesis-001#1", "alice", "bob", "alice").await.is_err());
    // poor buyer fails, nothing moves
    assert!(storage.buy_listing(&l.id, "bob").await.is_err());
    assert_eq!(storage.spiral_balance("bob").await.unwrap(), 30);
    // fund + buy
    storage.faucet_spiral("bob", 30).await.unwrap();
    let sold = storage.buy_listing(&l.id, "bob").await.unwrap();
    assert_eq!(sold.status, "sold");
    assert_eq!(storage.get_asset("genesis-001#1").await.unwrap().unwrap().owner, "bob");
    assert_eq!(storage.spiral_balance("bob").await.unwrap(), 10);
    assert_eq!(storage.spiral_balance("alice").await.unwrap(), 150);
    // second buy fails closed
    assert!(storage.buy_listing(&l.id, "alice").await.is_err());
}

#[tokio::test]
async fn marketplace_cancel_unlists() {
    let (storage, _dir) = test_storage("assets_cancel.redb");
    seed(&storage).await;
    storage.claim_token("genesis-001", "alice", "alice").await.unwrap();
    let l = storage.create_listing("genesis-001#1", "alice", 50).await.unwrap();
    assert!(storage.cancel_listing(&l.id, "mallory").await.is_err());
    let c = storage.cancel_listing(&l.id, "alice").await.unwrap();
    assert_eq!(c.status, "cancelled");
    // movable again
    assert!(storage.transfer_asset("genesis-001#1", "alice", "bob", "alice").await.is_ok());
    assert!(storage.list_open_listings(50).await.unwrap().is_empty());
}

#[tokio::test]
async fn swap_instance_lists_moves_many_atomically() {
    let (storage, _dir) = test_storage("assets_swaplist.redb");
    seed(&storage).await;
    storage.claim_token("genesis-001", "alice", "alice").await.unwrap();
    storage.claim_token("genesis-001", "bob", "bob").await.unwrap();
    storage
        .swap_instance_lists(&["genesis-001#1".to_string()], "alice", &["genesis-001#2".to_string()], "bob", "alice")
        .await
        .unwrap();
    assert_eq!(storage.get_asset("genesis-001#1").await.unwrap().unwrap().owner, "bob");
    // unknown instance fails, nothing moves
    assert!(storage
        .swap_instance_lists(&["genesis-001#2".to_string()], "bob", &["genesis-001#404".to_string()], "alice", "bob")
        .await
        .is_err());
    assert_eq!(storage.get_asset("genesis-001#2").await.unwrap().unwrap().owner, "alice");
}

#[tokio::test]
async fn swap_instances_is_atomic() {
    let (storage, _dir) = test_storage("assets_swap.redb");
    seed(&storage).await;
    storage.claim_token("genesis-001", "alice", "alice").await.unwrap();
    storage.claim_token("genesis-001", "bob", "bob").await.unwrap();
    storage
        .swap_instances("genesis-001#1", "alice", "genesis-001#2", "bob", "alice")
        .await
        .unwrap();
    assert_eq!(storage.get_asset("genesis-001#1").await.unwrap().unwrap().owner, "bob");
    assert_eq!(storage.get_asset("genesis-001#2").await.unwrap().unwrap().owner, "alice");
    // wrong side fails, nothing moves
    assert!(storage
        .swap_instances("genesis-001#1", "alice", "genesis-001#2", "bob", "alice")
        .await
        .is_err());
    assert_eq!(storage.get_asset("genesis-001#1").await.unwrap().unwrap().owner, "bob");
}
