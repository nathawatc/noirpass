//! Reproducible metadata scan benchmark without new dependencies.
//!
//! Run: `nix develop -c cargo test --release metadata_scan_benchmark -- --ignored --nocapture`.
//! Seeds only isolated metadata; ciphertext is not read by these queries.
//! Reports warmed median and maximum of nine samples, excluding fixture setup.

use std::time::{Duration, Instant};

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

#[test]
#[ignore = "opt-in performance measurement; uses a temporary metadata-only fixture"]
fn metadata_scan_benchmark() {
    for count in [100usize, 1_000, 10_000, 100_000] {
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
                        ("account", "fixture"),
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
        let query = attrs(&[("service", "benchmark")]);
        let (list, list_max) = sample(|| {
            let items = store.list_items(&collections[0].id).unwrap();
            assert_eq!(std::hint::black_box(items).len(), count / 10);
        });
        let (search, search_max) = sample(|| {
            let items = store.search_items(&query).unwrap();
            assert_eq!(std::hint::black_box(items).len(), count);
        });
        let (repeated, repeated_max) = sample(|| {
            let total: usize = collections
                .iter()
                .map(|collection| {
                    std::hint::black_box(store.list_items(&collection.id).unwrap()).len()
                })
                .sum();
            assert_eq!(total, count);
        });
        let (once, once_max) = sample(|| {
            let items = store.search_items(&HashMap::new()).unwrap();
            assert_eq!(std::hint::black_box(items).len(), count);
        });
        println!(
            "items={count}; median/max: list={list:?}/{list_max:?}; search={search:?}/{search_max:?}; startup scans repeated={repeated:?}/{repeated_max:?}; once={once:?}/{once_max:?}"
        );
    }
}
