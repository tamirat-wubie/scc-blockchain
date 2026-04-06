use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::tension::TensionValue;
use crate::{AgentId, Hash, MerkleRoot, NormId, ObjectId, TransitionId};

/// Typed causal graph — DAG with typed edges per v2.0 spec.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CausalGraph {
    pub vertices: HashSet<CausalVertex>,
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
    pub fn is_acyclic(&self) -> bool {
        // Simple DFS-based cycle detection.
        use std::collections::HashMap;
        let mut adj: HashMap<CausalVertex, Vec<CausalVertex>> = HashMap::new();
        for edge in &self.edges {
            let (src, tgt) = edge.endpoints();
            adj.entry(src).or_default().push(tgt);
        }

        #[derive(PartialEq)]
        enum Color {
            White,
            Gray,
            Black,
        }
        let mut color: HashMap<CausalVertex, Color> = HashMap::new();
        for v in &self.vertices {
            color.insert(v.clone(), Color::White);
        }

        fn dfs(
            v: &CausalVertex,
            adj: &HashMap<CausalVertex, Vec<CausalVertex>>,
            color: &mut HashMap<CausalVertex, Color>,
        ) -> bool {
            color.insert(v.clone(), Color::Gray);
            if let Some(neighbors) = adj.get(v) {
                for n in neighbors {
                    match color.get(n) {
                        Some(Color::Gray) => return false, // cycle found
                        Some(Color::White) => {
                            if !dfs(n, adj, color) {
                                return false;
                            }
                        }
                        _ => {}
                    }
                }
            }
            color.insert(v.clone(), Color::Black);
            true
        }

        for v in &self.vertices {
            if color.get(v) == Some(&Color::White) {
                if !dfs(v, &adj, &mut color) {
                    return false;
                }
            }
        }
        true
    }
}

/// Vertex types in the causal graph.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    CausedBy { source: CausalVertex, target: CausalVertex },
    DependsOn { source: CausalVertex, target: CausalVertex },
    AuthorizedBy { source: CausalVertex, target: CausalVertex },
    Proves { source: CausalVertex, target: CausalVertex },
    Violates { source: CausalVertex, target: CausalVertex },
    Compensates { source: CausalVertex, target: CausalVertex },
    Amends { source: CausalVertex, target: CausalVertex },
    DerivedFrom { source: CausalVertex, target: CausalVertex },
    ObservedBy { source: CausalVertex, target: CausalVertex },
    GovernedBy { source: CausalVertex, target: CausalVertex },
    ContainedBy { source: CausalVertex, target: CausalVertex },
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
