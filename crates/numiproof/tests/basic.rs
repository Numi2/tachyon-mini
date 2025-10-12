// numiproof/tests/basic.rs
use numiproof::{prove, verify, Graph};

#[test]
fn triangle_proves_and_verifies() {
    let g = Graph::new(3, vec![(0, 1), (1, 2), (0, 2)]).unwrap();
    let proof = prove(&g, &[0, 1, 2], 32, 1).unwrap();
    assert!(verify(&g, &proof));
}

#[test]
fn graph_binding_fails_on_modified_graph() {
    let g = Graph::new(4, vec![(0, 1), (1, 2), (2, 3), (0, 3)]).unwrap();
    let proof = prove(&g, &[0, 1, 2, 0], 16, 2).unwrap();
    // Different graph, same vertex count.
    let g2 = Graph::new(4, vec![(0, 2), (1, 3)]).unwrap();
    assert!(!verify(&g2, &proof));
}

#[test]
fn serialization_roundtrip_json_and_bincode() {
    let g = Graph::new(5, vec![(0,1),(1,2),(2,3),(3,4),(0,4)]).unwrap();
    let p = prove(&g, &[0,1,2,0,1], 8, 2).unwrap();

    // JSON
    let s = serde_json::to_string(&p).unwrap();
    let p2: numiproof::Proof = serde_json::from_str(&s).unwrap();
    assert!(verify(&g, &p2));

    // Bincode
    let bin = bincode::serialize(&p).unwrap();
    let p3: numiproof::Proof = bincode::deserialize(&bin).unwrap();
    assert!(verify(&g, &p3));
}

#[test]
fn wrong_parameters_rejected() {
    let g = Graph::new(2, vec![(0,1)]).unwrap();
    assert!(prove(&g, &[0,1], 0, 1).is_err());
    assert!(prove(&g, &[0,1], 1, 0).is_err());
}

#[test]
fn invalid_coloring_rejected() {
    let g = Graph::new(3, vec![(0,1),(1,2),(0,2)]).unwrap();
    assert!(prove(&g, &[0,0,1], 8, 1).is_err());
}
