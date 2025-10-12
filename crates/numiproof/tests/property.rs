// numiproof/tests/property.rs
use numiproof::{prove, verify, Graph};
use proptest::prelude::*;

/// Build a 3-colorable graph by construction.
/// Pick a random coloring, then include only edges across unequal colors.
fn graph_from_coloring(n: usize, colors: &[u8], target_edges: usize) -> Graph {
    // Collect all cross-color pairs u < v with colors[u] != colors[v]
    let mut edges = Vec::new();
    for u in 0..n {
        for v in (u + 1)..n {
            if colors[u] != colors[v] {
                edges.push((u, v));
            }
        }
    }
    // Downsample deterministically if too many
    let take = target_edges.min(edges.len().max(1));
    // Simple subselection: every k-th edge.
    let step = (edges.len().max(1) + take - 1) / take;
    let selected: Vec<_> = edges.into_iter().step_by(step).take(take).collect();
    Graph::new(n, selected).unwrap()
}

proptest! {
    #[test]
    fn proves_and_verifies_random_graphs(
        n in 3usize..15,
        rounds in 1usize..8,
        target_edges in 1usize..40,
        edges_per_round_hint in 1usize..5,
        colors in prop::collection::vec(0u8..3, 3..15)
    ) {
        let n = n.min(colors.len());
        let colors = &colors[..n];

        // Ensure at least two colors appear to avoid empty edge set.
        let distinct = {
            let mut seen = [false;3];
            for &c in colors { seen[c as usize] = true; }
            seen.iter().filter(|&&b| b).count()
        };
        prop_assume!(distinct >= 2);

        let g = graph_from_coloring(n, colors, target_edges);
        // edges_per_round must be >=1
        let epr = edges_per_round_hint.min(g.edges().len().max(1)).max(1);

        let proof = prove(&g, colors, rounds, epr).unwrap();
        prop_assert!(verify(&g, &proof));

        // Graph binding: change one edge; verification must fail.
        if g.edges().len() >= 1 {
            // Replace last edge with a different valid cross-color edge if possible, else drop it.
            let mut alt_edges = g.edges().to_vec();
            let last = alt_edges.pop().unwrap();
            let mut replaced = false;
            'outer: for u in 0..n {
                for v in (u+1)..n {
                    if colors[u] != colors[v] && (u,v) != last {
                        alt_edges.push((u,v));
                        replaced = true;
                        break 'outer;
                    }
                }
            }
            if !replaced {
                // fallback: drop last edge making a different graph
            }
            let g2 = Graph::new(n, alt_edges).unwrap();
            prop_assert!(!verify(&g2, &proof));
        }
    }
}
