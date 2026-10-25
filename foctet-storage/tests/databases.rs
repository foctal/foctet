use foctet_core::{BodyEnvelopeLimits, IdentityKeyPair, PeerIdentity, StorageRecord};
use foctet_http::{AsyncReplayStore, ReplayCheck};
use foctet_storage::{Dialect, SqlStore, StoredRecord};
use x25519_dalek::{PublicKey, StaticSecret};

async fn exercise(store: SqlStore) {
    store.initialize().await.unwrap();
    store.initialize().await.unwrap();
    let writer = IdentityKeyPair::from_secret_key_bytes([41; 32]);
    let pin = PeerIdentity::new(writer.public_key());
    let secret = StaticSecret::from([51; 32]);
    let public = PublicKey::from(&secret).to_bytes();
    let limits = BodyEnvelopeLimits::default();
    let make = |version| {
        StoredRecord::seal(
            &[0, 255, 128, 0, 39],
            public,
            b"key",
            StorageRecord::new(b"tenant/table", b"row", version),
            &writer,
            &limits,
        )
        .unwrap()
    };
    let record = make(1);
    let key = [93; 32];
    assert!(store.compare_and_swap(key, None, &record).await.unwrap());
    assert!(!store.compare_and_swap(key, None, &record).await.unwrap());
    let loaded = store.get(key).await.unwrap().unwrap();
    assert_eq!(loaded.ciphertext, record.ciphertext);
    assert_eq!(loaded.signature, record.signature);
    assert_eq!(
        loaded
            .open(
                secret.to_bytes(),
                StorageRecord::new(b"tenant/table", b"row", 1),
                pin,
                &limits
            )
            .unwrap(),
        [0, 255, 128, 0, 39]
    );
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let store = store.clone();
        let record = make(2);
        tasks.push(tokio::spawn(async move {
            store.compare_and_swap(key, Some(1), &record).await.unwrap()
        }));
    }
    let mut winners = 0;
    for task in tasks {
        winners += usize::from(task.await.unwrap());
    }
    assert_eq!(winners, 1);
    assert!(
        !store
            .compare_and_swap(key, Some(1), &make(2))
            .await
            .unwrap()
    );
    assert!(
        loaded
            .open(
                secret.to_bytes(),
                StorageRecord::new(b"tenant/table", b"row", 2),
                pin,
                &limits
            )
            .is_err()
    );
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let store = store.clone();
        tasks.push(tokio::spawn(async move {
            store.check_and_insert(&[17; 16], 200, 100).await
        }));
    }
    let mut winners = 0;
    for task in tasks {
        if matches!(task.await.unwrap(), Ok(ReplayCheck::Accepted)) {
            winners += 1;
        }
    }
    assert_eq!(winners, 1);
    assert_eq!(
        store.check_and_insert(&[17; 16], 200, 150).await.unwrap(),
        ReplayCheck::Replay
    );
    assert_eq!(store.prune_replay(200).await.unwrap(), 1);
    assert_eq!(
        store.check_and_insert(&[17; 16], 300, 201).await.unwrap(),
        ReplayCheck::Accepted
    );
    store.close().await;
}
#[tokio::test]
async fn sqlite_roundtrip_cas_replay_and_rollback() {
    exercise(
        SqlStore::connect("sqlite::memory:", Dialect::Sqlite, 1024 * 1024)
            .await
            .unwrap(),
    )
    .await;
}
#[tokio::test]
async fn sqlite_restart_preserves_records_and_replay() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("db.sqlite");
    let url = format!("sqlite://{}?mode=rwc", path.display());
    let store = SqlStore::connect(&url, Dialect::Sqlite, 1024)
        .await
        .unwrap();
    store.initialize().await.unwrap();
    let record = StoredRecord {
        version: 1,
        ciphertext: vec![0, 255, 1],
        signature: [8; 64],
    };
    store
        .compare_and_swap([5; 32], None, &record)
        .await
        .unwrap();
    store.check_and_insert(&[1; 16], 100, 1).await.unwrap();
    store.close().await;
    let restored = SqlStore::connect(&url, Dialect::Sqlite, 1024)
        .await
        .unwrap();
    assert_eq!(
        restored.get([5; 32]).await.unwrap().unwrap().ciphertext,
        record.ciphertext
    );
    assert_eq!(
        restored.check_and_insert(&[1; 16], 100, 2).await.unwrap(),
        ReplayCheck::Replay
    );
}
/// Run against a disposable database. Never point at an application database.
#[tokio::test]
#[ignore = "requires FOCTET_TEST_DATABASE_URL and disposable database"]
async fn server_database_conformance() {
    let url = std::env::var("FOCTET_TEST_DATABASE_URL").expect("test URL");
    let dialect = if url.starts_with("postgres") {
        Dialect::Postgres
    } else {
        Dialect::Mysql
    };
    exercise(SqlStore::connect(&url, dialect, 1024 * 1024).await.unwrap()).await;
    let restored = SqlStore::connect(&url, dialect, 1024 * 1024).await.unwrap();
    assert_eq!(restored.get([93; 32]).await.unwrap().unwrap().version, 2);
    assert_eq!(
        restored
            .check_and_insert(&[17; 16], 300, 202)
            .await
            .unwrap(),
        ReplayCheck::Replay
    );
    restored.close().await;
}

#[cfg(feature = "turso")]
#[tokio::test]
#[ignore = "requires FOCTET_TEST_TURSO_URL and disposable libSQL server"]
async fn turso_remote_conformance() {
    use foctet_storage::turso::TursoStore;
    let url = std::env::var("FOCTET_TEST_TURSO_URL").expect("test URL");
    let store = TursoStore::connect(url.clone(), String::new(), 1024 * 1024)
        .await
        .unwrap();
    store.initialize().await.unwrap();
    let writer = IdentityKeyPair::from_secret_key_bytes([12; 32]);
    let pin = PeerIdentity::new(writer.public_key());
    let secret = StaticSecret::from([14; 32]);
    let public = PublicKey::from(&secret).to_bytes();
    let limits = BodyEnvelopeLimits::default();
    let record = StoredRecord::seal(
        b"Turso\0\xff",
        public,
        b"key",
        StorageRecord::new(b"ns", b"id", 1),
        &writer,
        &limits,
    )
    .unwrap();
    assert!(
        store
            .compare_and_swap([24; 32], None, &record)
            .await
            .unwrap()
    );
    assert!(
        !store
            .compare_and_swap([24; 32], None, &record)
            .await
            .unwrap()
    );
    let read = store.get([24; 32]).await.unwrap().unwrap();
    assert_eq!(read.ciphertext, record.ciphertext);
    assert_eq!(
        read.open(
            secret.to_bytes(),
            StorageRecord::new(b"ns", b"id", 1),
            pin,
            &limits
        )
        .unwrap(),
        b"Turso\0\xff"
    );
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let url = url.clone();
        tasks.push(tokio::spawn(async move {
            let client = TursoStore::connect(url, String::new(), 1024 * 1024)
                .await
                .unwrap();
            client.check_and_insert(&[22; 16], 100, 1).await.unwrap()
        }));
    }
    let mut winners = 0;
    for task in tasks {
        if task.await.unwrap() == ReplayCheck::Accepted {
            winners += 1;
        }
    }
    assert_eq!(winners, 1);
    assert_eq!(store.prune_replay(100).await.unwrap(), 1);
    let next = StoredRecord::seal(
        b"updated",
        public,
        b"key",
        StorageRecord::new(b"ns", b"id", 2),
        &writer,
        &limits,
    )
    .unwrap();
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let url = url.clone();
        let next = next.clone();
        tasks.push(tokio::spawn(async move {
            let client = TursoStore::connect(url, String::new(), 1024 * 1024)
                .await
                .unwrap();
            client
                .compare_and_swap([24; 32], Some(1), &next)
                .await
                .unwrap()
        }));
    }
    let mut wins = 0;
    for task in tasks {
        wins += usize::from(task.await.unwrap());
    }
    assert_eq!(wins, 1);
    let restored = TursoStore::connect(url, String::new(), 1024 * 1024)
        .await
        .unwrap();
    let loaded = restored.get([24; 32]).await.unwrap().unwrap();
    assert_eq!(
        loaded
            .open(
                secret.to_bytes(),
                StorageRecord::new(b"ns", b"id", 2),
                pin,
                &limits
            )
            .unwrap(),
        b"updated"
    );
    assert!(
        read.open(
            secret.to_bytes(),
            StorageRecord::new(b"ns", b"id", 2),
            pin,
            &limits
        )
        .is_err()
    );
}

#[tokio::test]
async fn mismatched_dialect_is_rejected_before_connecting() {
    assert!(
        SqlStore::connect("sqlite::memory:", Dialect::Postgres, 1024)
            .await
            .is_err()
    );
    assert!(
        SqlStore::connect("postgres://127.0.0.1:1/db", Dialect::Sqlite, 1024)
            .await
            .is_err()
    );
}
