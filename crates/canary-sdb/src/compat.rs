use crate::{
    database::{LiveDatabase, SdbClass, SdbField},
};

#[derive(Clone, Debug)]
pub struct SdbEntryClass {
    pub id: u64,
    pub name: String,
    pub vtable: Option<u64>,
    pub confidence: f32,
}

#[derive(Clone, Debug)]
pub struct SdbEntryField {
    pub class_id: u64,
    pub offset: i64,
    pub type_name: String,
    pub confidence: f32,
}

impl From<SdbClass> for SdbEntryClass {
    fn from(c: SdbClass) -> Self {
        Self {
            id: c.class_id,
            name: format!("Class_{:X}", c.class_id),
            vtable: c.vtable,
            confidence: c.confidence,
        }
    }
}

impl From<SdbField> for SdbEntryField {
    fn from(f: SdbField) -> Self {
        Self {
            class_id: f.class_id,
            offset: f.offset,
            type_name: format!("{:?}", f.dominant_type),
            confidence: f.confidence,
        }
    }
}

pub struct CompatibilityView {
    pub classes: Vec<SdbEntryClass>,
    pub fields: Vec<SdbEntryField>,
}

pub fn build_compat_view(sdb: &LiveDatabase) -> CompatibilityView {
    let mut classes = Vec::new();
    let mut fields = Vec::new();

    for c in sdb.classes.values() {
        classes.push(SdbEntryClass::from(c.clone()));
    }

    for f in sdb.fields.values() {
        fields.push(SdbEntryField::from(f.clone()));
    }

    CompatibilityView { classes, fields }
}

pub fn stable_only(view: CompatibilityView, min_conf: f32) -> CompatibilityView {
    CompatibilityView {
        classes: view.classes.into_iter()
            .filter(|c| c.confidence >= min_conf)
            .collect(),

        fields: view.fields.into_iter()
            .filter(|f| f.confidence >= min_conf)
            .collect(),
    }
}
