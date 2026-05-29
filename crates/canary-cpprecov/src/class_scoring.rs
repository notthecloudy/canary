use canary_sdb::types::ClassHypothesis;

pub fn recompute_confidence(classes: &mut [ClassHypothesis]) {
    for c in classes.iter_mut() {
        let e = &c.evidence;

        let raw = 0.35 * e.vtable_score
            + 0.25 * e.callgraph_score
            + 0.20 * e.this_usage_score
            + 0.20 * e.rtti_score;

        let dampened = raw.powf(1.5);

        c.confidence = dampened.clamp(0.0, 0.99);
    }
}
