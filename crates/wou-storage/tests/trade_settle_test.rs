use wou_storage::{SettleTradeError, WouStorage};

fn test_storage(name: &str) -> (WouStorage, tempfile::TempDir) {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let redb_path = temp_dir.path().join(name);
    let storage = WouStorage::new("redis://127.0.0.1:6379", redb_path.to_str().unwrap())
        .expect("Failed to initialize WouStorage");
    (storage, temp_dir)
}

fn open_trade_json(id: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "id": id,
        "from_account": "alice",
        "to_account": null,
        "offered": ["genesis-001"],
        "requested": ["genesis-002"],
        "status": "open",
        "created_at": 0,
    }))
    .unwrap()
}

fn accepted_trade_json(id: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "id": id,
        "from_account": "alice",
        "to_account": null,
        "offered": ["genesis-001"],
        "requested": ["genesis-002"],
        "status": "accepted",
        "created_at": 0,
    }))
    .unwrap()
}

#[tokio::test]
async fn settle_trade_swaps_atomically() {
    let (storage, _dir) = test_storage("settle_ok.redb");
    storage
        .add_to_inventory("alice", vec!["genesis-001".to_string()])
        .await
        .unwrap();
    storage
        .add_to_inventory("bob", vec!["genesis-002".to_string()])
        .await
        .unwrap();
    storage.save_trade("t1", &open_trade_json("t1")).await.unwrap();

    storage
        .settle_trade(
            "t1",
            "alice",
            "bob",
            &["genesis-001".to_string()],
            &["genesis-002".to_string()],
            &accepted_trade_json("t1"),
        )
        .await
        .unwrap();

    assert_eq!(storage.get_inventory("alice").await.unwrap(), vec!["genesis-002"]);
    assert_eq!(storage.get_inventory("bob").await.unwrap(), vec!["genesis-001"]);
    let raw = storage.get_trade("t1").await.unwrap().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(v.get("status").and_then(|s| s.as_str()), Some("accepted"));
}

#[tokio::test]
async fn settle_trade_rejects_double_settle() {
    let (storage, _dir) = test_storage("settle_double.redb");
    storage
        .add_to_inventory("alice", vec!["genesis-001".to_string()])
        .await
        .unwrap();
    storage
        .add_to_inventory("bob", vec!["genesis-002".to_string()])
        .await
        .unwrap();
    storage.save_trade("t1", &open_trade_json("t1")).await.unwrap();

    storage
        .settle_trade(
            "t1",
            "alice",
            "bob",
            &["genesis-001".to_string()],
            &["genesis-002".to_string()],
            &accepted_trade_json("t1"),
        )
        .await
        .unwrap();

    // Second settlement (the double-spend race) must fail cleanly,
    // and inventories must be untouched by the failed attempt.
    let err = storage
        .settle_trade(
            "t1",
            "alice",
            "bob",
            &["genesis-001".to_string()],
            &["genesis-002".to_string()],
            &accepted_trade_json("t1"),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, SettleTradeError::NotOpen));
    assert_eq!(storage.get_inventory("alice").await.unwrap(), vec!["genesis-002"]);
    assert_eq!(storage.get_inventory("bob").await.unwrap(), vec!["genesis-001"]);
}

#[tokio::test]
async fn settle_trade_rejects_ownership_change_and_missing() {
    let (storage, _dir) = test_storage("settle_race.redb");
    storage
        .add_to_inventory("alice", vec!["genesis-001".to_string()])
        .await
        .unwrap();
    storage
        .add_to_inventory("bob", vec!["genesis-002".to_string()])
        .await
        .unwrap();
    storage.save_trade("t1", &open_trade_json("t1")).await.unwrap();

    // Bob's card moves away between route check and commit.
    storage
        .remove_from_inventory("bob", vec!["genesis-002".to_string()])
        .await
        .unwrap();
    let err = storage
        .settle_trade(
            "t1",
            "alice",
            "bob",
            &["genesis-001".to_string()],
            &["genesis-002".to_string()],
            &accepted_trade_json("t1"),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, SettleTradeError::OwnershipChanged));
    // Failed settlement moves nothing.
    assert_eq!(storage.get_inventory("alice").await.unwrap(), vec!["genesis-001"]);

    // Unknown trade id.
    let err = storage
        .settle_trade(
            "nope",
            "alice",
            "bob",
            &["genesis-001".to_string()],
            &["genesis-002".to_string()],
            &accepted_trade_json("nope"),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, SettleTradeError::NotOpen));
}
