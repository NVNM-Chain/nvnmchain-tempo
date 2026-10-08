//! What each mode costs as the corpus grows. A measurement, not an assertion:
//! `cargo test --release -p tempo-anchoring-index --test scan -- --ignored --nocapture`

use std::{
    path::Path,
    time::{Duration, Instant},
};

use tempo_anchoring_index::{Mode, Store};

/// Names shaped like the corpus's, `us-<state><court><n>`, so a query's selectivity is real.
fn names(count: u64) -> Vec<(u64, String)> {
    const STATES: [&str; 10] = ["ca", "ny", "tx", "wa", "fl", "oh", "ga", "pa", "il", "mi"];
    const COURTS: [&str; 6] = ["sup", "app", "dist", "ctapp", "superct", "oytermct"];
    (1..=count)
        .map(|id| {
            let state = STATES[(id % 10) as usize];
            let court = COURTS[(id % 6) as usize];
            (id, format!("us-{state}{court}{id}"))
        })
        .collect()
}

fn dir_bytes(path: &Path) -> u64 {
    std::fs::read_dir(path)
        .expect("index dir")
        .map(|entry| {
            let entry = entry.expect("entry");
            match entry.file_type().expect("file type").is_dir() {
                true => dir_bytes(&entry.path()),
                false => entry.metadata().expect("metadata").len(),
            }
        })
        .sum()
}

/// The best of five, and what it found.
fn best(mut run: impl FnMut() -> usize) -> (Duration, usize) {
    let mut hits = 0;
    let mut best = Duration::MAX;
    for _ in 0..5 {
        let at = Instant::now();
        hits = run();
        best = best.min(at.elapsed());
    }
    (best, hits)
}

#[test]
#[ignore = "measurement"]
fn every_mode_over_a_growing_corpus() {
    println!(
        "\n{:>9}  {:>8}  {:>7}  {:>9}  {:>9}  {:>9}  {:>9}  {:>9}  {:>9}",
        "names", "build", "disk", "exact", "prefix", "common", "rare", "woven", "≤2 chars"
    );
    for count in [2_182u64, 50_000, 250_000, 1_000_000] {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("index");
        let mut store = Store::open(&path).expect("open");

        let rows = names(count);
        let at = Instant::now();
        for chunk in rows.chunks(10_000) {
            store.insert(chunk).expect("insert");
        }
        let build = at.elapsed();

        let reader = store.reader();
        let time =
            |mode, query: &str| best(|| reader.search(mode, query, 0, 50).expect("search").len());
        let one = &rows[(count / 2) as usize].1;

        let (exact, hits) = time(Mode::Exact, one);
        assert_eq!(hits, 1);
        let (prefix, _) = time(Mode::Prefix, one);
        // One name in thirty holds it, so the page fills early.
        let (common, hits) = time(Mode::Contains, "nyoytermct");
        assert_eq!(hits, 50.min(count as usize / 30));
        // Held by none: a scan reads the whole corpus to say so.
        let (rare, hits) = time(Mode::Contains, "qqq");
        assert_eq!(hits, 0);
        // Held by none, though every trigram of it is held by many: what the probe count is for.
        let (woven, hits) = time(Mode::Contains, "oytermctca");
        assert_eq!(hits, 0);
        // Shorter than a trigram, which reads the names.
        let (short, hits) = time(Mode::Contains, "zz");
        assert_eq!(hits, 0);

        println!(
            "{count:>9}  {build:>8.2?}  {:>4} MB  {exact:>9.3?}  {prefix:>9.3?}  {common:>9.3?}  {rare:>9.3?}  {woven:>9.3?}  {short:>9.3?}",
            dir_bytes(&path) / 1_000_000,
        );
    }
    println!();
}
