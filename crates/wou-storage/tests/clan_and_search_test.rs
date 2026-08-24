use wou_core::{Clan, ClanMember, ClanRole, PlayerAccount, EmbeddedWallets};
use wou_storage::WouStorage;

#[tokio::test]
async fn test_clan_lifecycle_and_search() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let redb_path = temp_dir.path().join("test_clans.redb");
    let redis_url = "redis://127.0.0.1:6379";

    let storage = WouStorage::new(redis_url, redb_path.to_str().unwrap())
        .expect("Failed to initialize WouStorage");

    // 1. Create 2 players
    let mut p1 = PlayerAccount::new_with_wallets(
        "user_101".into(),
        Some("falcon382".into()),
        Some("Falcon 382".into()),
        EmbeddedWallets {
            evm_address: "0x111".into(),
            solana_address: "Sol111".into(),
            icp_principal: "icp111".into(),
            bitcoin_address: "bc1111".into(),
        },
    );
    p1.profile.custom_attributes.insert("animal_emoji".into(), "🦅".into());
    storage.save_account(&p1).await.expect("save p1");

    let mut p2 = PlayerAccount::new_with_wallets(
        "user_102".into(),
        Some("panther901".into()),
        Some("Panther 901".into()),
        EmbeddedWallets {
            evm_address: "0x222".into(),
            solana_address: "Sol222".into(),
            icp_principal: "icp222".into(),
            bitcoin_address: "bc1222".into(),
        },
    );
    p2.profile.custom_attributes.insert("animal_emoji".into(), "🐆".into());
    storage.save_account(&p2).await.expect("save p2");

    // 2. Search for players by query
    let search_falcon = storage.search_players("falcon", 10).await.expect("search falcon");
    assert_eq!(search_falcon.len(), 1);
    assert_eq!(search_falcon[0].username, "falcon382");
    assert_eq!(search_falcon[0].animal_emoji.as_deref(), Some("🦅"));

    let search_all = storage.search_players("901", 10).await.expect("search 901");
    assert_eq!(search_all.len(), 1);
    assert_eq!(search_all[0].username, "panther901");

    // 3. Create Clan [SOW]
    let clan = Clan {
        tag: "SOW".into(),
        name: "Shadows Vanguard".into(),
        description: "Official Shadows of War Competitive Guild".into(),
        leader_id: "user_101".into(),
        leader_username: "falcon382".into(),
        avatar_url: None,
        banner_url: None,
        member_count: 1,
        created_at: 1787400000,
    };
    let leader_member = ClanMember {
        account_id: "user_101".into(),
        username: "falcon382".into(),
        display_name: "Falcon 382".into(),
        avatar_url: None,
        animal_emoji: Some("🦅".into()),
        role: ClanRole::Leader,
        joined_at: 1787400000,
    };

    storage.create_clan(&clan, &leader_member).await.expect("create clan");

    // 4. Retrieve Clan Details & Members
    let fetched_clan = storage.get_clan("SOW").await.expect("get clan").expect("clan exists");
    assert_eq!(fetched_clan.name, "Shadows Vanguard");
    assert_eq!(fetched_clan.member_count, 1);

    let members = storage.get_clan_members("SOW").await.expect("get members");
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].role, ClanRole::Leader);

    // 5. Join Clan as P2
    let p2_member = ClanMember {
        account_id: "user_102".into(),
        username: "panther901".into(),
        display_name: "Panther 901".into(),
        avatar_url: None,
        animal_emoji: Some("🐆".into()),
        role: ClanRole::Member,
        joined_at: 1787400100,
    };
    storage.join_clan("SOW", &p2_member).await.expect("join clan");

    let updated_clan = storage.get_clan("SOW").await.expect("get clan").expect("clan exists");
    assert_eq!(updated_clan.member_count, 2);

    let updated_members = storage.get_clan_members("SOW").await.expect("get members");
    assert_eq!(updated_members.len(), 2);

    // 6. Leave Clan
    storage.leave_clan("SOW", "user_102").await.expect("leave clan");
    let after_leave_clan = storage.get_clan("SOW").await.expect("get clan").expect("clan exists");
    assert_eq!(after_leave_clan.member_count, 1);
}
