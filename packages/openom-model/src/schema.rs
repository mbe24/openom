//! JSON Schema validation of a serialized canonical model.

use serde_json::Value;

/// A compiled validator for the canonical model against **JSON Schema — Draft 2020-12**
/// (<https://json-schema.org/draft/2020-12/schema>). This type is the single place that dialect is
/// pinned in Rust; the schema documents declare the same dialect through their `$schema` keyword. It
/// sits behind the `validation` feature and off the default/wasm build so `jsonschema` never bloats
/// the browser bundle.
pub struct ModelSchema {
    validator: jsonschema::Validator,
}

impl ModelSchema {
    /// Compile the checked-in canonical-model schema.
    pub fn new() -> Self {
        let model: Value = serde_json::from_str(include_str!("../schema/model.schema.json"))
            .expect("model.schema.json is valid JSON");
        let name: Value = serde_json::from_str(include_str!("../schema/name.schema.json"))
            .expect("name.schema.json is valid JSON");
        // Register the name fragment so the model's `$ref` to it (by $id) resolves.
        let validator = jsonschema::options()
            .with_resource(
                "https://openom.dev/schema/name.schema.json",
                jsonschema::Resource::from_contents(name)
                    .expect("name.schema.json is a valid schema resource"),
            )
            .build(&model)
            .expect("model.schema.json is a valid schema");
        Self { validator }
    }

    /// Does `instance` satisfy the schema?
    pub fn is_valid(&self, instance: &Value) -> bool {
        self.validator.is_valid(instance)
    }
}

impl Default for ModelSchema {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;

    #[test]
    fn real_model_satisfies_schema_and_junk_does_not() {
        let s = ModelSchema::new();

        let mut src = SeededIdSource::new(11);
        let mut m = Model::new(TreeId::generate(&mut src));
        let p = m.create_node(NodeKind::Person, &mut src);
        let f = m.create_node(NodeKind::Family, &mut src);
        m.add_edge(RelationshipType::ParentChild, f, p, &mut src).unwrap();
        m.add_event(EventType::Birth, p, Some(2000), &mut src).unwrap();
        // An embedded name exercises the cross-schema $ref into name.schema.json.
        m.add_name(
            p,
            Name {
                id: NameId::generate(&mut src),
                role: Some("birth".into()),
                form_of: None,
                primary: true,
                script: None,
                culture: None,
                parts: vec![Part::new("given", "Ada"), Part::new("family", "Lovelace")],
            },
        )
        .unwrap();

        let v = serde_json::to_value(&m).unwrap();
        assert!(s.is_valid(&v), "a real serialized Model (with an embedded name) must satisfy the schema");

        // Missing the required tables → invalid.
        assert!(!s.is_valid(&serde_json::json!({})));

        // An illegal enum value → invalid.
        let mut bad = v.clone();
        let nodes = bad.get_mut("nodes").unwrap().as_object_mut().unwrap();
        let first = nodes.keys().next().unwrap().clone();
        nodes
            .get_mut(&first)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("kind".into(), serde_json::json!("Alien"));
        assert!(!s.is_valid(&bad), "an illegal node kind must fail validation");
    }
}
