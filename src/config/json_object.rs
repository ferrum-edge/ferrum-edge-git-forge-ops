//! Serde helpers that require a JSON **object** where a struct is expected,
//! mirroring ferrum-edge's `src/util/json_object.rs`.
//!
//! serde's derived struct visitors also implement `visit_seq`, so an array is
//! otherwise accepted as a *positional* construction of the struct: a short
//! array leaves every remaining `#[serde(default)]` field at its default. For a
//! plugin trigger that turns `consumer: []` into `consumer: {presence:
//! present}` — a valid predicate the gateway would then match — where Edge
//! rejects the array outright.
//!
//! The wrappers force the map branch and hand the original map access to the
//! wrapped type's own `Deserialize`, so field defaults keep working and
//! `serde_ignored` (the strict loader's unknown-field detector) still sees
//! every key inside the object.

use std::fmt;
use std::marker::PhantomData;

use serde::de::value::MapAccessDeserializer;
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer};

struct ObjectVisitor<T>(PhantomData<fn() -> T>);

impl<'de, T: Deserialize<'de>> Visitor<'de> for ObjectVisitor<T> {
    type Value = T;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON object")
    }

    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<T, A::Error> {
        T::deserialize(MapAccessDeserializer::new(map))
    }
}

/// `T` that must be read from an object; a sequence or scalar is an error.
struct JsonObject<T>(T);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for JsonObject<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserialize_object(deserializer).map(JsonObject)
    }
}

/// `deserialize_with` helper for a required struct-valued field.
pub(crate) fn deserialize_object<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    deserializer.deserialize_map(ObjectVisitor(PhantomData))
}

/// `#[serde(default, deserialize_with = "...")]` helper for an
/// `Option<SomeStruct>` field: absent or `null` stays `None`, an object
/// deserializes normally, and a sequence or scalar is rejected.
pub(crate) fn deserialize_optional_object<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<JsonObject<T>>::deserialize(deserializer).map(|object| object.map(|object| object.0))
}

/// Optional list of objects: every element must be an object.
pub(crate) fn deserialize_optional_object_vec<'de, D, T>(
    deserializer: D,
) -> Result<Option<Vec<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<Vec<JsonObject<T>>>::deserialize(deserializer)
        .map(|objects| objects.map(|objects| objects.into_iter().map(|object| object.0).collect()))
}
