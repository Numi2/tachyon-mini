// numiproof/examples/demo.rs
use numiproof::{prove, verify, Graph};

fn main() {
    // K_{3} with proper 3-coloring [0,1,2]
    let g = Graph::new(3, vec![(0,1),(1,2),(0,2)]).unwrap();
    let proof = prove(&g, &[0,1,2], 32, 1).unwrap();
    println!("verify: {}", verify(&g, &proof));

    // Serialize to JSON and back.
    let s = serde_json::to_string(&proof).unwrap();
    let proof2: numiproof::Proof = serde_json::from_str(&s).unwrap();
    println!("verify after JSON roundtrip: {}", verify(&g, &proof2));
}
