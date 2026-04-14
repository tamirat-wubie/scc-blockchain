use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::tension::TensionValue;
use crate::{AgentId, Hash, MerkleRoot, NormId, ObjectId, TransitionId};

/// Typed causal graph — DAG with typed edges per v2.0 spec.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CausalGraph {
    pub vertices: BTreeSet<CausalVertex>,
    pub edges: Vec<CausalEdge>,
}

impl CausalGraph {
    pub fn add_vertex(&mut self, v: CausalVertex) {
        self.vertices.insert(v);
    }

    pub fn add_edge(&mut self, e: CausalEdge) {
        self.edges.push(e);
    }

    /// Check for cycles in the causal graph (INV-17 per v2.1 FIX B-16).
    /// Returns true if the graph is acyclic.
    /// Uses iterative DFS to prevent stack overflow on deep graphs.
    /// Includes phantom vertices (in edges but not in vertex set).
    pub fn is_acyclic(&self) -> bool {
        use std::collections::HashMap;

        // Build adjacency list.
        let mut adj: HashMap<CausalVertex, Vec<CausalVertex>> = HashMap::new();
        // Collect ALL vertices: both declared and referenced in edges.
        let mut all_vertices: BTreeSet<CausalVertex> = self.vertices.clone();
        for edge in &self.edges {
            let (src, tgt) = edge.endpoints();
            all_vertices.insert(src.clone());
            all_vertices.insert(tgt.clone());
            adj.entry(src).or_default().push(tgt);
        }

        #[derive(Clone, Copy, PartialEq)]
        enum Color {
            White,
            Gray,
            Black,
        }

        let mut color: HashMap<CausalVertex, Color> = all_vertices
            .iter()
            .map(|v| (v.clone(), Color::White))
            .collect();

        // Iterative DFS with explicit stack (prevents stack overflow).
        // Uses index-based neighbor access to avoid cloning neighbor Vecs.
        let empty: Vec<CausalVertex> = Vec::new();
        for start in &all_vertices {
            if color.get(start) != Some(&Color::White) {
                continue;
            }
            let mut stack: Vec<(CausalVertex, usize)> = vec![(start.clone(), 0)];
            color.insert(start.clone(), Color::Gray);

            while let Some(stack_top) = stack.last_mut() {
                let neighbors = adj.get(&stack_top.0).unwrap_or(&empty);
                if stack_top.1 < neighbors.len() {
                    let neighbor = neighbors[stack_top.1].clone();
                    stack_top.1 += 1;
                    match color.get(&neighbor) {
                        Some(Color::Gray) => return false,
                        Some(Color::White) => {
                            color.insert(neighbor.clone(), Color::Gray);
                            stack.push((neighbor, 0));
                        }
                        _ => {}
                    }
                } else {
                    let v = stack_top.0.clone();
                    color.insert(v, Color::Black);
                    stack.pop();
                }
            }
        }
        true
    }
}

/// Vertex types in the causal graph.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CausalVertex {
    Transition(TransitionId),
    Receipt(Hash),
    Object(ObjectId),
    Proof(Hash),
    Actor(AgentId),
    Policy(Hash),
    GovernanceDecision(Hash),
    NormMutation(NormId),
    Block(Hash),
}

/// Typed causal edge — 12 edge types per spec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CausalEdge {
    CausedBy {
        source: CausalVertex,
        target: CausalVertex,
    },
    DependsOn {
        source: CausalVertex,
        target: CausalVertex,
    },
    AuthorizedBy {
        source: CausalVertex,
        target: CausalVertex,
    },
    Proves {
        source: CausalVertex,
        target: CausalVertex,
    },
    Violates {
        source: CausalVertex,
        target: CausalVertex,
    },
    Compensates {
        source: CausalVertex,
        target: CausalVertex,
    },
    Amends {
        source: CausalVertex,
        target: CausalVertex,
    },
    DerivedFrom {
        source: CausalVertex,
        target: CausalVertex,
    },
    ObservedBy {
        source: CausalVertex,
        target: CausalVertex,
    },
    GovernedBy {
        source: CausalVertex,
        target: CausalVertex,
    },
    ContainedBy {
        source: CausalVertex,
        target: CausalVertex,
    },
    TensionPropagates {
        source: CausalVertex,
        target: CausalVertex,
        delta: TensionValue,
    },
}

impl CausalEdge {
    pub fn endpoints(&self) -> (CausalVertex, CausalVertex) {
        match self {
            Self::CausedBy { source, target }
            | Self::DependsOn { source, target }
            | Self::AuthorizedBy { source, target }
            | Self::Proves { source, target }
            | Self::Violates { source, target }
            | Self::Compensates { source, target }
            | Self::Amends { source, target }
            | Self::DerivedFrom { source, target }
            | Self::ObservedBy { source, target }
            | Self::GovernedBy { source, target }
            | Self::ContainedBy { source, target } => (source.clone(), target.clone()),
            Self::TensionPropagates { source, target, .. } => (source.clone(), target.clone()),
        }
    }
}

/// Delta to the causal graph added by a single block.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CausalGraphDelta {
    pub new_vertices: Vec<CausalVertex>,
    pub new_edges: Vec<CausalEdge>,
    pub causal_root: MerkleRoot,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_graph_is_acyclic() {
        let graph = CausalGraph::default();
        assert!(graph.is_acyclic());
    }

    #[test]
    fn test_linear_graph_is_acyclic() {
        let mut graph = CausalGraph::default();
        let v1 = CausalVertex::Transition([1u8; 32]);
        let v2 = CausalVertex::Transition([2u8; 32]);
        let v3 = CausalVertex::Transition([3u8; 32]);
        graph.add_vertex(v1.clone());
        graph.add_vertex(v2.clone());
        graph.add_vertex(v3.clone());
        graph.add_edge(CausalEdge::CausedBy {
            source: v2.clone(),
            target: v1.clone(),
        });
        graph.add_edge(CausalEdge::CausedBy {
            source: v3.clone(),
            target: v2.clone(),
        });
        assert!(graph.is_acyclic());
    }

    #[test]
    fn test_cycle_detected() {
        let mut graph = CausalGraph::default();
        let v1 = CausalVertex::Transition([1u8; 32]);
        let v2 = CausalVertex::Transition([2u8; 32]);
        graph.add_vertex(v1.clone());
        graph.add_vertex(v2.clone());
        graph.add_edge(CausalEdge::CausedBy {
            source: v1.clone(),
            target: v2.clone(),
        });
        graph.add_edge(CausalEdge::CausedBy {
            source: v2.clone(),
            target: v1.clone(),
        });
        assert!(!graph.is_acyclic());
    }

    #[test]
    fn test_self_loop_detected() {
        let mut graph = CausalGraph::default();
        let v1 = CausalVertex::Transition([1u8; 32]);
        graph.add_vertex(v1.clone());
        graph.add_edge(CausalEdge::CausedBy {
            source: v1.clone(),
            target: v1.clone(),
        });
        assert!(!graph.is_acyclic());
    }

    #[test]
    fn test_edge_endpoints() {
        let src = CausalVertex::Transition([1u8; 32]);
        let tgt = CausalVertex::Actor([2u8; 32]);
        let edge = CausalEdge::AuthorizedBy {
            source: src.clone(),
            target: tgt.clone(),
        };
        let (s, t) = edge.endpoints();
        assert_eq!(s, src);
        assert_eq!(t, tgt);
    }

    #[test]
    fn test_diamond_graph_acyclic() {
        let mut graph = CausalGraph::default();
        let a = CausalVertex::Transition([1u8; 32]);
        let b = CausalVertex::Transition([2u8; 32]);
        let c = CausalVertex::Transition([3u8; 32]);
        let d = CausalVertex::Transition([4u8; 32]);
        graph.add_vertex(a.clone());
        graph.add_vertex(b.clone());
        graph.add_vertex(c.clone());
        graph.add_vertex(d.clone());
        // Diamond: a→b, a→c, b→d, c→d.
        graph.add_edge(CausalEdge::CausedBy {
            source: b.clone(),
            target: a.clone(),
        });
        graph.add_edge(CausalEdge::CausedBy {
            source: c.clone(),
            target: a.clone(),
        });
        graph.add_edge(CausalEdge::CausedBy {
            source: d.clone(),
            target: b.clone(),
        });
        graph.add_edge(CausalEdge::CausedBy {
            source: d.clone(),
            target: c.clone(),
        });
        assert!(graph.is_acyclic());
    }

    #[test]
    fn test_causal_graph_delta_default() {
        let delta = CausalGraphDelta::default();
        assert!(delta.new_vertices.is_empty());
        assert!(delta.new_edges.is_empty());
        assert_eq!(delta.causal_root, [0u8; 32]);
    }
}
