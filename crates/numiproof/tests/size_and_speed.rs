// numiproof/tests/size_and_speed.rs
use numiproof::{prove, verify, Graph};

#[test]
fn proof_sizes_stay_reasonable() {
    let n = 64;
    // 3-partite complete graph across partitions of size ~n/3.
    let part = n/3;
    let mut edges = Vec::new();
    for u in 0..n {
        for v in (u+1)..n {
            let cu = (u/part) as u8 % 3;
            let cv = (v/part) as u8 % 3;
            if cu != cv {
                edges.push((u,v));
            }
        }
    }
    let g = Graph::new(n, edges).unwrap();
    let colors: Vec<u8> = (0..n).map(|i| ((i/part) as u8)%3).collect();
    let rounds = 16usize;
    let epr = 4usize;

    let proof = prove(&g, &colors, rounds, epr).unwrap();
    assert!(verify(&g, &proof));

    let json = serde_json::to_vec(&proof).unwrap();
    // Not a hard security bound. Just a sanity ceiling for CI.
    assert!(json.len() < 3_000_000, "json size {} too large", json.len());
}
