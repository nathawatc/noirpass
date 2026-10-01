//! Reproducible metadata scan benchmark without new dependencies.
//!
//! Run: `nix develop -c cargo test --release metadata_scan_benchmark -- --ignored --nocapture`.
//! Seeds only isolated metadata; ciphertext is not read by these queries.
//! Reports warmed median and maximum of nine samples, excluding fixture setup.
//! Also measures the first lookup and a lookup after writer admission.

use std::time::{Duration, Instant};

use redb::{ReadableDatabase, ReadableTable};

use super::*;

fn sample(mut operation: impl FnMut()) -> (Duration, Duration) {
    operation();
    let mut samples = Vec::new();
    for _ in 0..9 {
        let start = Instant::now();
        operation();
        samples.push(start.elapsed());
    }
    samples.sort_unstable();
    (samples[4], samples[8])
}

fn metadata_fixture(count: usize) -> (tempfile::TempDir, Store, Vec<CollectionMeta>) {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let collections: Vec<_> = (0..10)
        .map(|n| {
            store
                .create_collection(&format!("collection {n}"), None)
                .unwrap()
        })
        .collect();
    let txn = store.db.begin_write().unwrap();
    {
        let mut items = txn.open_table(ITEMS).unwrap();
        for n in 0..count {
            let metadata = ItemMeta {
                id: format!("{n:032x}"),
                collection: collections[n % collections.len()].id.clone(),
                label: format!("benchmark item {n}"),
                attributes: attrs(&[
                    ("service", "benchmark"),
                    ("account", &format!("account-{n}")),
                    ("application", "noirpass"),
                ]),
                content_type: "text/plain".into(),
                ciphertext_sha256: Some(ciphertext_sha256(b"benchmark ciphertext")),
                created: 1,
                modified: 1,
            };
            let bytes = serde_json::to_vec(&metadata).unwrap();
            items
                .insert(metadata.id.as_str(), bytes.as_slice())
                .unwrap();
        }
    }
    txn.commit().unwrap();
    (tmp, store, collections)
}

/// Previous full-scan behavior, run against exactly the same committed fixture.
fn full_scan(
    store: &Store,
    collection: Option<&str>,
    query: &HashMap<String, String>,
) -> Vec<ItemMeta> {
    let txn = store.db.begin_read().unwrap();
    let items = txn.open_table(ITEMS).unwrap();
    let mut out = Vec::new();
    for entry in items.iter().unwrap() {
        let (key, value) = entry.unwrap();
        let metadata = decode_item(key.value(), value.value()).unwrap();
        if collection.is_none_or(|id| metadata.collection == id)
            && query
                .iter()
                .all(|(name, value)| metadata.attributes.get(name) == Some(value))
        {
            out.push(metadata);
        }
    }
    out
}

#[test]
#[ignore = "opt-in performance measurement; uses a temporary metadata-only fixture"]
fn metadata_scan_benchmark() {
    for count in [100usize, 1_000, 10_000, 100_000] {
        let (_tmp, store, collections) = metadata_fixture(count);
        let selective = attrs(&[("account", &format!("account-{}", count / 2))]);
        let start = Instant::now();
        assert_eq!(store.search_items(&selective).unwrap().len(), 1);
        let cold = start.elapsed();
        let (list, list_max) = sample(|| {
            let items = store.list_items(&collections[0].id).unwrap();
            assert_eq!(std::hint::black_box(items).len(), count / 10);
        });
        let (list_scan, _) = sample(|| {
            let items = full_scan(&store, Some(&collections[0].id), &HashMap::new());
            assert_eq!(std::hint::black_box(items).len(), count / 10);
        });
        let (search, search_max) = sample(|| {
            let items = store.search_items(&selective).unwrap();
            assert_eq!(std::hint::black_box(items).len(), 1);
        });
        let (search_scan, _) = sample(|| {
            let items = full_scan(&store, None, &selective);
            assert_eq!(std::hint::black_box(items).len(), 1);
        });
        let (all, all_max) = sample(|| {
            let items = store.search_items(&HashMap::new()).unwrap();
            assert_eq!(std::hint::black_box(items).len(), count);
        });
        let common = attrs(&[("service", "benchmark")]);
        let (broad, broad_max) = sample(|| {
            assert_eq!(
                std::hint::black_box(store.search_items(&common).unwrap()).len(),
                count
            );
        });
        let (broad_scan, _) = sample(|| {
            assert_eq!(
                std::hint::black_box(full_scan(&store, None, &common)).len(),
                count
            );
        });
        store
            .set_alias("benchmark", Some(&collections[0].id))
            .unwrap();
        let start = Instant::now();
        assert_eq!(store.search_items(&selective).unwrap().len(), 1);
        let rebuild = start.elapsed();
        println!(
            "items={count}; cold={cold:?}; rebuild={rebuild:?}; median/max: indexed list={list:?}/{list_max:?} (scan={list_scan:?}); indexed selective search={search:?}/{search_max:?} (scan={search_scan:?}); broad search={broad:?}/{broad_max:?} (scan={broad_scan:?}); all items={all:?}/{all_max:?}"
        );
    }
}
