use canary_sdb::types::ClassHypothesis;

pub fn collapse_low_confidence(classes: &mut Vec<ClassHypothesis>) {
    let mut merged: Vec<ClassHypothesis> = Vec::new();

    for c in classes.iter() {
        if let Some(existing) = merged.iter_mut().find(|e| e.vtable_addr == c.vtable_addr) {
            // soft merge
            existing.confidence = (existing.confidence + c.confidence) / 2.0;

            for m in &c.methods {
                if !existing.methods.contains(m) {
                    existing.methods.push(*m);
                }
            }
        } else {
            merged.push(c.clone());
        }
    }

    *classes = merged;
}
