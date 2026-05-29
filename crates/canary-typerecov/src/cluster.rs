//! Clustering algorithms for struct inference.

use canary_sdb::SemanticDatabase;
use indexmap::{IndexMap, IndexSet};

#[derive(Debug, Clone)]
pub struct TypeCluster {
    pub members: IndexSet<String>,
    pub confidence: f32,
}

pub fn cluster_types(sdb: &SemanticDatabase) -> IndexMap<String, TypeCluster> {
    let mut clusters = IndexMap::new();

    // Cluster fields into types based on the class vtable they belong to.
    for field in &sdb.interpretations.field_models {
        let cluster_name = format!("Type_vtable_{:x}", field.class_vtable);

        let cluster = clusters.entry(cluster_name).or_insert_with(|| TypeCluster {
            members: IndexSet::new(),
            confidence: 0.0,
        });

        // Add the field offset as a member of this type cluster
        let field_member = format!("offset_{}", field.offset);
        cluster.members.insert(field_member);

        // Update confidence based on read/write entropy
        let field_conf = field.confidence + (field.methods_touching as f32 * 0.1);
        if field_conf > cluster.confidence {
            cluster.confidence = field_conf;
        }
    }

    clusters
}
