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
    /// Uses iterative DFS to prevent stack overflow on deep graphs.
    /// Includes phantom vertices (in edges but not in vertex set).
    pub fn is_acyclic(&self) -> bool {
        use std::collections::HashMap;

        // Build adjacency list.
        let mut adj: HashMap<CausalVertex, Vec<CausalVertex>> = HashMap::new();
        // Collect ALL vertices: both declared and referenced in edges.
        let mut all_vertices: HashSet<CausalVertex> = self.vertices.clone();
        for edge in &self.edges {
            let (src, tgt) = edge.endpoints();
            all_vertices.insert(src.clone());
            all_vertices.insert(tgt.clone());
            adj.entry(src).or_default().push(tgt);
        }

        #[derive(Clone, Copy, PartialEq)]
        enum Color { White, Gray, Black }

        let mut color: HashMap<CausalVertex, Color> = all_vertices
            .iter()
            .map(|v| (v.clone(), Color::White))
            .collect();

        // Iterative DFS with explicit stack (prevents stack overflow).
        for start in &all_vertices {
            if color.get(start) != Some(&Color::White) {
                continue;
            }
            // Stack entries: (vertex, neighbor_index, is_entering)
            let mut stack: Vec<(CausalVertex, usize)> = vec![(start.clone(), 0)];
            color.insert(start.clone(), Color::Gray);

            while let Some((v, idx)) = stack.last_mut() {
                let neighbors = adj.get(v).cloned().unwrap_or_default();
                if *idx < neighbors.len() {
                    let neighbor = neighbors[*idx].clone();
                    *idx += 1;
                    match color.get(&neighbor) {
                        Some(Color::Gray) => return false, // Cycle found.
                        Some(Color::White) => {
                            color.insert(neighbor.clone(), Color::Gray);
                            stack.push((neighbor, 0));
                        }
                        _ => {} // Black — already fully explored.
                    }
                } else {
                    color.insert(v.clone(), Color::Black);
                    stack.pop();
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
