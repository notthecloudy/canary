use canary_sdb::types::ClassHypothesis;
use indexmap::IndexMap;

pub fn run(classes: &mut Vec<ClassHypothesis>) {
    // STEP 1: HARD FILTER
    classes.retain(|c| c.confidence >= 0.55);

    // STEP 2: CLUSTER LIMIT ENFORCEMENT
    let mut per_vtable: IndexMap<u64, Vec<ClassHypothesis>> = IndexMap::new();

    for c in classes.drain(..) {
        per_vtable.entry(c.vtable_addr).or_default().push(c);
    }

    let mut final_classes = Vec::new();

    for (_, mut group) in per_vtable {
        // keep top 1–3 only
        group.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let limit = group.len().min(3);

        for i in 0..limit {
            final_classes.push(group[i].clone());
        }
    }

    *classes = final_classes;
}
