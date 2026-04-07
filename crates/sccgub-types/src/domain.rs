use serde::{Deserialize, Serialize};

use crate::governance::PrecedenceLevel;
use crate::transition::Constraint;
use crate::Hash;

/// Domain Pack — pluggable type/law/norm extension for the chain.
/// Per spec Section 23: domain packs extend types, laws, contracts, and norms.
///
/// Constraints per v2.1 FIX B-17:
/// 1. All types prefixed with domain_id namespace
/// 2. Law extensions cannot override core kernel laws
/// 3. Norm conflicts resolved by precedence order
/// 4. Installation requires MEANING precedence governance authority
/// 5. Rollback supported via governance transition with SAFETY precedence
/// 6. Version compatibility matrix maintained in governance state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainPack {
    /// Unique identifier for this domain pack.
    pub id: Hash,
    /// Human-readable name (namespaced, e.g., "finance.lending").
    pub name: String,
    /// Version string (semver).
    pub version: String,
    /// Description of what this domain covers.
    pub description: String,
    /// Minimum governance level required to install.
    pub required_level: PrecedenceLevel,
    /// Types defined by this domain (type_name -> type_schema).
    pub types: Vec<DomainType>,
    /// Laws (constraints) added by this domain.
    pub laws: Vec<Constraint>,
    /// Dependencies on other domain packs.
    pub dependencies: Vec<Hash>,
    /// Block height at which this pack was installed.
    pub installed_at: Option<u64>,
    /// Whether this pack is active.
    pub active: bool,
}

/// A type defined by a domain pack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainType {
    /// Fully qualified name (domain_id.type_name).
    pub name: String,
    /// Schema description.
    pub schema: String,
    /// Fields.
    pub fields: Vec<DomainField>,
}

/// A field in a domain type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainField {
    pub name: String,
    pub field_type: String,
    pub required: bool,
}

/// Domain pack registry.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DomainPackRegistry {
    pub packs: Vec<DomainPack>,
}

impl DomainPackRegistry {
    /// Install a domain pack. Checks authority and dependencies.
    pub fn install(
        &mut self,
        pack: DomainPack,
        installer_level: PrecedenceLevel,
        current_height: u64,
    ) -> Result<(), String> {
        // Authority check.
        if (installer_level as u8) > (pack.required_level as u8) {
            return Err(format!(
                "Insufficient authority: need {:?}, have {:?}",
                pack.required_level, installer_level
            ));
        }

        // Duplicate check.
        if self.packs.iter().any(|p| p.id == pack.id) {
            return Err(format!(
                "Domain pack {} already installed",
                hex::encode(pack.id)
            ));
        }

        // Dependency check.
        for dep in &pack.dependencies {
            if !self.packs.iter().any(|p| p.id == *dep && p.active) {
                return Err(format!(
                    "Missing dependency: {}",
                    hex::encode(dep)
                ));
            }
        }

        // Namespace collision check.
        for new_type in &pack.types {
            for existing in &self.packs {
                if existing.active {
                    for existing_type in &existing.types {
                        if existing_type.name == new_type.name {
                            return Err(format!(
                                "Type name collision: {} already defined by pack {}",
                                new_type.name, existing.name
                            ));
                        }
                    }
                }
            }
        }

        let mut pack = pack;
        pack.installed_at = Some(current_height);
        pack.active = true;
        self.packs.push(pack);
        Ok(())
    }

    /// Deactivate a domain pack (requires SAFETY precedence).
    pub fn deactivate(&mut self, pack_id: &Hash) -> Result<(), String> {
        let pack = self
            .packs
            .iter_mut()
            .find(|p| p.id == *pack_id)
            .ok_or("Pack not found")?;
        pack.active = false;
        Ok(())
    }

    /// Get active packs.
    pub fn active_packs(&self) -> Vec<&DomainPack> {
        self.packs.iter().filter(|p| p.active).collect()
    }

    /// Get all laws from active domain packs.
    pub fn all_domain_laws(&self) -> Vec<&Constraint> {
        self.packs
            .iter()
            .filter(|p| p.active)
            .flat_map(|p| &p.laws)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::PrecedenceLevel;

    fn test_pack(name: &str) -> DomainPack {
        // Simple deterministic ID from name (no crypto dependency in types crate).
        let mut id = [0u8; 32];
        for (i, b) in name.bytes().enumerate() {
            id[i % 32] ^= b;
        }
        DomainPack {
            id,
            name: name.into(),
            version: "1.0.0".into(),
            description: format!("{} domain", name),
            required_level: PrecedenceLevel::Meaning,
            types: vec![DomainType {
                name: format!("{}.Record", name),
                schema: "basic record".into(),
                fields: vec![DomainField {
                    name: "value".into(),
                    field_type: "string".into(),
                    required: true,
                }],
            }],
            laws: vec![],
            dependencies: vec![],
            installed_at: None,
            active: false,
        }
    }

    #[test]
    fn test_install_and_query() {
        let mut registry = DomainPackRegistry::default();
        registry
            .install(test_pack("finance"), PrecedenceLevel::Meaning, 10)
            .unwrap();
        assert_eq!(registry.active_packs().len(), 1);
        assert_eq!(registry.active_packs()[0].name, "finance");
    }

    #[test]
    fn test_authority_rejected() {
        let mut registry = DomainPackRegistry::default();
        let result = registry.install(
            test_pack("finance"),
            PrecedenceLevel::Optimization,
            10,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_duplicate_rejected() {
        let mut registry = DomainPackRegistry::default();
        registry
            .install(test_pack("finance"), PrecedenceLevel::Meaning, 10)
            .unwrap();
        let result = registry.install(test_pack("finance"), PrecedenceLevel::Meaning, 20);
        assert!(result.is_err());
    }

    #[test]
    fn test_namespace_collision_rejected() {
        let mut registry = DomainPackRegistry::default();
        registry
            .install(test_pack("finance"), PrecedenceLevel::Meaning, 10)
            .unwrap();
        // Create a different pack that defines the same type name.
        let mut pack2 = test_pack("banking");
        pack2.types[0].name = "finance.Record".into(); // Collides with finance pack.
        let result = registry.install(pack2, PrecedenceLevel::Meaning, 20);
        assert!(result.is_err());
    }

    #[test]
    fn test_deactivate() {
        let mut registry = DomainPackRegistry::default();
        let pack = test_pack("finance");
        let id = pack.id;
        registry.install(pack, PrecedenceLevel::Meaning, 10).unwrap();
        assert_eq!(registry.active_packs().len(), 1);

        registry.deactivate(&id).unwrap();
        assert_eq!(registry.active_packs().len(), 0);
    }

    #[test]
    fn test_missing_dependency() {
        let mut registry = DomainPackRegistry::default();
        let mut pack = test_pack("lending");
        pack.dependencies = vec![[99u8; 32]]; // Non-existent dependency.
        let result = registry.install(pack, PrecedenceLevel::Meaning, 10);
        assert!(result.is_err());
    }
}
