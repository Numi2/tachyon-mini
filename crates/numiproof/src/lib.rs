// numiproof/src/lib.rs
//! numiproof: post-quantum ZK proofs via BLAKE3 and Fiat–Shamir.
//! Numan Thabit 2025 experimental
//! Statement: "Graph G is 3-colorable." Relation proved by opening random edges.
//! Commitments: C_i = BLAKE3(D_COMMIT || r_i || color_i') with per-round random permutation of {0,1,2}.
//! Non-interactive challenges from BLAKE3 over transcript and graph (Fiat–Shamir).
//! Assumption: collision resistance of BLAKE3. Quantum: Grover gives sqrt speedup; 256-bit output is conservative.
//!
//! Public API:
//! - Graph::new(n, edges) -> Result<Graph, ZkError>
//! - prove(&graph, &coloring, rounds, edges_per_round) -> Result<Proof, ZkError>
//! - verify(&graph, &proof) -> bool
//!
//! Example:
//! ```no_run
//! use numiproof::*;
//! let g = Graph::new(3, vec![(0,1),(1,2),(0,2)]).unwrap();
//! let proof = prove(&g, &[0,1,2], 64, 1).unwrap();
//! assert!(verify(&g, &proof));
//! ```

use rand::{rngs::OsRng, Rng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const HASH_LEN: usize = 32;
const D_COMMIT: &[u8] = b"numiproof.commit.v1";
const D_SEED: &[u8] = b"numiproof.seed.v1";
const D_SAMPLE: &[u8] = b"numiproof.sample.v1";

#[derive(Debug, Error)]
pub enum ZkError {
    #[error("invalid graph: {0}")]
    InvalidGraph(&'static str),
    #[error("invalid coloring")]
    InvalidColoring,
    #[error("parameter must be > 0")]
    BadParameter,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Graph {
    n: usize,
    edges: Vec<(usize, usize)>,
}

impl Graph {
    /// Create a graph with `n` vertices (0..n-1) and given undirected edges.
    pub fn new(n: usize, mut edges: Vec<(usize, usize)>) -> Result<Self, ZkError> {
        if n == 0 {
            return Err(ZkError::InvalidGraph("n == 0"));
        }
        if edges.is_empty() {
            return Err(ZkError::InvalidGraph("must have at least one edge"));
        }
        for e in edges.iter_mut() {
            if e.0 == e.1 {
                return Err(ZkError::InvalidGraph("self-loop not allowed"));
            }
            if e.0 >= n || e.1 >= n {
                return Err(ZkError::InvalidGraph("edge endpoint out of range"));
            }
            if e.1 < e.0 {
                // normalize order
                std::mem::swap(&mut e.0, &mut e.1);
            }
        }
        Ok(Self { n, edges })
    }

    pub fn n(&self) -> usize {
        self.n
    }

    pub fn edges(&self) -> &[(usize, usize)] {
        &self.edges
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof {
    rounds: Vec<RoundProof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RoundProof {
    commitments: Vec<[u8; HASH_LEN]>, // per-vertex
    challenges: Vec<usize>,            // edge indices opened this round
    openings: Vec<OpenPair>,           // one per challenge
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct OpenPair {
    u: usize,
    v: usize,
    color_u: u8,       // permuted color in {0,1,2}
    rand_u: [u8; 32],
    color_v: u8,
    rand_v: [u8; 32],
}

/// Produce a non-interactive ZK proof that `coloring` is a proper 3-coloring of `graph`.
/// `rounds` ≥ 1 and `edges_per_round` ≥ 1. Higher means lower soundness error.
/// Returns error if coloring invalid or parameters bad.
pub fn prove(
    graph: &Graph,
    coloring: &[u8],
    rounds: usize,
    edges_per_round: usize,
) -> Result<Proof, ZkError> {
    if rounds == 0 || edges_per_round == 0 {
        return Err(ZkError::BadParameter);
    }
    if coloring.len() != graph.n() || !coloring.iter().all(|&c| c < 3) {
        return Err(ZkError::InvalidColoring);
    }
    // Check proper coloring.
    for &(u, v) in graph.edges() {
        if coloring[u] == coloring[v] {
            return Err(ZkError::InvalidColoring);
        }
    }

    let mut rng = OsRng;
    let mut rounds_out = Vec::with_capacity(rounds);

    for round in 0..rounds {
        // Random permutation of {0,1,2}
        let mut perm = [0u8, 1u8, 2u8];
        for i in (1..3).rev() {
            let j = rng.gen_range(0..=i);
            perm.swap(i, j);
        }

        // Per-vertex commitments with fresh randomness.
        let mut commitments = Vec::with_capacity(graph.n());
        let mut permuted_colors: Vec<u8> = Vec::with_capacity(graph.n());
        let mut rands: Vec<[u8; 32]> = Vec::with_capacity(graph.n());

        for &c in coloring {
            let pc = perm[c as usize];
            let mut r = [0u8; 32];
            rng.fill_bytes(&mut r);
            let com = commit_bytes(&[pc], &r);
            commitments.push(com);
            permuted_colors.push(pc);
            rands.push(r);
        }

        // Fiat–Shamir: derive deterministic challenges from commitments and graph.
        let seed = derive_seed(graph, round as u64, &commitments);
        let challenges = sample_edges(graph, &seed, edges_per_round);

        // Open the endpoints of each challenged edge.
        let mut openings = Vec::with_capacity(challenges.len());
        for &eidx in &challenges {
            let (u, v) = graph.edges()[eidx];
            openings.push(OpenPair {
                u,
                v,
                color_u: permuted_colors[u],
                rand_u: rands[u],
                color_v: permuted_colors[v],
                rand_v: rands[v],
            });
        }

        rounds_out.push(RoundProof {
            commitments,
            challenges,
            openings,
        });
    }

    Ok(Proof { rounds: rounds_out })
}

/// Verify a non-interactive 3-coloring proof.
pub fn verify(graph: &Graph, proof: &Proof) -> bool {
    if proof.rounds.is_empty() {
        return false;
    }
    for (round_idx, round) in proof.rounds.iter().enumerate() {
        if round.commitments.len() != graph.n() {
            return false;
        }
        if round.challenges.is_empty() || round.openings.len() != round.challenges.len() {
            return false;
        }
        // Recompute Fiat–Shamir challenges.
        let seed = derive_seed(graph, round_idx as u64, &round.commitments);
        let expected = sample_edges(graph, &seed, round.challenges.len());
        if expected != round.challenges {
            return false;
        }
        // Check openings.
        for (i, &eidx) in round.challenges.iter().enumerate() {
            if eidx >= graph.edges().len() {
                return false;
            }
            let (u, v) = graph.edges()[eidx];
            let open = &round.openings[i];
            if open.u != u || open.v != v {
                return false;
            }
            if open.color_u >= 3 || open.color_v >= 3 || open.color_u == open.color_v {
                return false;
            }
            // Commitments must match the revealed values.
            let cu = commit_bytes(&[open.color_u], &open.rand_u);
            let cv = commit_bytes(&[open.color_v], &open.rand_v);
            if cu != round.commitments[u] || cv != round.commitments[v] {
                return false;
            }
        }
    }
    true
}

// --- helpers ---

fn commit_bytes(msg: &[u8], rand: &[u8; 32]) -> [u8; HASH_LEN] {
    let mut h = blake3::Hasher::new();
    h.update(D_COMMIT);
    h.update(rand);
    h.update(msg);
    let out = h.finalize();
    let mut bytes = [0u8; HASH_LEN];
    bytes.copy_from_slice(out.as_bytes());
    bytes
}

fn derive_seed(graph: &Graph, round: u64, commitments: &[[u8; HASH_LEN]]) -> [u8; HASH_LEN] {
    let mut h = blake3::Hasher::new();
    h.update(D_SEED);
    let n = graph.n() as u64;
    let m = graph.edges().len() as u64;
    h.update(&n.to_le_bytes());
    h.update(&m.to_le_bytes());
    // Bind the exact graph by hashing ordered edges.
    for &(u, v) in graph.edges() {
        h.update(&(u as u64).to_le_bytes());
        h.update(&(v as u64).to_le_bytes());
    }
    h.update(&round.to_le_bytes());
    for c in commitments {
        h.update(c);
    }
    let out = h.finalize();
    let mut bytes = [0u8; HASH_LEN];
    bytes.copy_from_slice(out.as_bytes());
    bytes
}

fn sample_edges(graph: &Graph, seed: &[u8; HASH_LEN], k: usize) -> Vec<usize> {
    let m = graph.edges().len() as u64;
    debug_assert!(m > 0, "graph must have at least one edge");
    let mut out = Vec::with_capacity(k);
    for ctr in 0u64..(k as u64) {
        let mut h = blake3::Hasher::new();
        h.update(D_SAMPLE);
        h.update(seed);
        h.update(&ctr.to_le_bytes());
        let x = h.finalize();
        let mut eight = [0u8; 8];
        eight.copy_from_slice(&x.as_bytes()[..8]);
        let idx = u64::from_le_bytes(eight) % m;
        out.push(idx as usize);
    }
    out
}

// --- tests ---
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn triangle_ok() {
        let g = Graph::new(3, vec![(0, 1), (1, 2), (0, 2)]).unwrap();
        let proof = prove(&g, &[0, 1, 2], 16, 1).unwrap();
        assert!(verify(&g, &proof));
    }

    #[test]
    fn rejects_zero_params() {
        let g = Graph::new(2, vec![(0, 1)]).unwrap();
        assert!(prove(&g, &[0, 1], 0, 1).is_err());
        assert!(prove(&g, &[0, 1], 1, 0).is_err());
    }

    #[test]
    fn bad_graphs_rejected() {
        assert!(Graph::new(0, vec![]).is_err());
        assert!(Graph::new(2, vec![]).is_err());
        assert!(Graph::new(2, vec![(0, 0)]).is_err());
        assert!(Graph::new(2, vec![(0, 2)]).is_err());
    }

    #[test]
    fn invalid_coloring_rejected() {
        let g = Graph::new(3, vec![(0, 1), (1, 2), (0, 2)]).unwrap();
        assert!(prove(&g, &[0, 0, 1], 8, 1).is_err());
    }

    #[test]
    fn tamper_detected() {
        let g = Graph::new(3, vec![(0, 1), (1, 2), (0, 2)]).unwrap();
        let mut p = prove(&g, &[0, 1, 2], 8, 1).unwrap();
        p.rounds[0].openings[0].color_u = 3; // out of range
        assert!(!verify(&g, &p));
    }

    #[test]
    fn challenge_binding() {
        let g = Graph::new(4, vec![(0, 1), (1, 2), (2, 3), (0, 3)]).unwrap();
        let proof = prove(&g, &[0, 1, 2, 0], 4, 2).unwrap();
        // Mutate challenges -> verify must fail
        let mut p2 = proof.clone();
        p2.rounds[0].challenges.reverse();
        assert!(!verify(&g, &p2));
    }
}
