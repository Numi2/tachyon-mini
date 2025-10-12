// numiproof/tests/tamper.rs
use numiproof::{prove, verify, Graph};
use serde_json::{self, Value};

fn make_triangle() -> (Graph, numiproof::Proof) {
    let g = Graph::new(3, vec![(0, 1), (1, 2), (0, 2)]).unwrap();
    let p = prove(&g, &[0, 1, 2], 8, 1).unwrap();
    (g, p)
}

#[test]
fn tamper_commitment_detected() {
    let (g, p) = make_triangle();
    let mut v: Value = serde_json::to_value(&p).unwrap();
    // Flip one byte of vertex 0 commitment in round 0.
    let b = &mut v["rounds"][0]["commitments"][0][0];
    *b = Value::from(b.as_u64().unwrap() ^ 0x01);
    let bad: numiproof::Proof = serde_json::from_value(v).unwrap();
    assert!(!verify(&g, &bad));
}

#[test]
fn tamper_opening_detected() {
    let (g, p) = make_triangle();
    let mut v: Value = serde_json::to_value(&p).unwrap();
    // Force equal colors on a revealed edge to violate constraint.
    let cu = v["rounds"][0]["openings"][0]["color_u"]
        .as_u64()
        .unwrap() as u8;
    v["rounds"][0]["openings"][0]["color_v"] = Value::from(cu as u64);
    let bad: numiproof::Proof = serde_json::from_value(v).unwrap();
    assert!(!verify(&g, &bad));
}

#[test]
fn tamper_challenge_detected() {
    let (g, p) = make_triangle();
    let mut v: Value = serde_json::to_value(&p).unwrap();
    // Change first challenge index.
    let old = v["rounds"][0]["challenges"][0].as_u64().unwrap();
    v["rounds"][0]["challenges"][0] = Value::from((old + 1) % (g.edges().len() as u64));
    let bad: numiproof::Proof = serde_json::from_value(v).unwrap();
    assert!(!verify(&g, &bad));
}
