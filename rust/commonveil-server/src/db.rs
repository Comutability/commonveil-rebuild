//! The two ways a backend function reaches the data, as in base44/shared/http.ts: `sr`, the
//! service role (every row), and `own`, the caller's own access (the entities' row rules).
use serde_json::{json, Value};

use crate::api::Result;
use crate::store::{Person, Store};

pub struct Db<'a> {
    store: &'a Store,
    person: Option<Person>,
}

impl<'a> Db<'a> {
    pub fn service(store: &'a Store) -> Self {
        Self {
            store,
            person: None,
        }
    }
    pub fn person(store: &'a Store, person: Person) -> Self {
        Self {
            store,
            person: Some(person),
        }
    }

    /// `entities[name].filter(query, sort, limit)`.
    pub fn filter(&self, name: &str, query: Value, sort: &str, limit: usize) -> Result<Vec<Value>> {
        let sort = json!(sort);
        Ok(match &self.person {
            None => self
                .store
                .filter(name, &query, Some(&sort), Some(limit as f64), None)?,
            Some(p) => self.store.person_filter(
                Some(p),
                name,
                &query,
                Some(&sort),
                Some(limit as f64),
                None,
            )?,
        })
    }
    pub fn first(&self, name: &str, query: Value, sort: &str) -> Result<Option<Value>> {
        Ok(self.filter(name, query, sort, 1)?.into_iter().next())
    }
    /// `entities[name].get(id)`; an error (not found, not allowed) is `None`, as `.catch(() => null)`.
    pub fn get(&self, name: &str, id: &str) -> Option<Value> {
        match &self.person {
            None => self.store.get(name, id).ok(),
            Some(p) => self.store.person_get(Some(p), name, id).ok(),
        }
    }
    pub fn create(&self, name: &str, data: Value) -> Result<Value> {
        Ok(match &self.person {
            None => self.store.create(name, &data, None)?,
            Some(p) => self.store.person_create(Some(p), name, &data)?,
        })
    }
    pub fn update(&self, name: &str, id: &str, data: Value) -> Result<Value> {
        Ok(match &self.person {
            None => self.store.update(name, id, &data)?,
            Some(p) => self.store.person_update(Some(p), name, id, &data)?,
        })
    }
    pub fn delete(&self, name: &str, id: &str) -> Result<()> {
        match &self.person {
            None => self.store.delete(name, id)?,
            Some(p) => self.store.person_delete(Some(p), name, id)?,
        };
        Ok(())
    }
    /// Service role only (as on Base44).
    pub fn delete_many(&self, name: &str, query: Value) -> Result<()> {
        self.store.delete_many(name, &query)?;
        Ok(())
    }
}

/// `{ ...a, ...b }` for JSON objects.
pub fn merged(a: &Value, b: &Value) -> Value {
    let mut out = a.clone();
    if let (Some(o), Some(n)) = (out.as_object_mut(), b.as_object()) {
        for (k, v) in n {
            o.insert(k.clone(), v.clone());
        }
    }
    out
}

/// A row's id as text.
pub fn id_of(row: &Value) -> &str {
    row["id"].as_str().unwrap_or("")
}
