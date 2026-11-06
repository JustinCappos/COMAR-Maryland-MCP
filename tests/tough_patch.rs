//! Regression tests for the vendored tough patch, using Maryland's real root metadata.

use tough::schema::key::Key;
use tough::schema::{Root, Signed};

const ROOT_V5: &str = include_str!("fixtures/maryland-dsd-law.5.root.json");

#[test]
fn parses_taf_root_with_trimmed_pem_key_ids() {
    // Two keys in this root are stored with a trailing newline after the PEM while their key
    // IDs were computed over the trimmed PEM, and all keys use rsa-pkcs1v15-sha256.
    let root: Signed<Root> = serde_json::from_str(ROOT_V5).expect("root v5 parses");
    assert_eq!(root.signed.keys.len(), 8);
}

#[test]
fn rejects_one_key_listed_under_two_ids() {
    let mut json: serde_json::Value = serde_json::from_str(ROOT_V5).unwrap();
    let keys = json["signed"]["keys"].as_object_mut().unwrap();
    // This key's listed ID is the trimmed-PEM form; its as-written ID is also accepted, so
    // listing it under both must be refused or it could count twice towards a threshold.
    let listed = "c4fc90e47d2b28d050e368b28a3474ad03aa29152a18f89657e62a5b3683ef07";
    let key: Key = serde_json::from_value(keys[listed].clone()).unwrap();
    let other_id = hex::encode(key.key_id().unwrap());
    assert_ne!(other_id, listed);
    keys.insert(other_id, keys[listed].clone());

    let err = serde_json::from_value::<Signed<Root>>(json).unwrap_err();
    assert!(err.to_string().contains("Duplicate key ID"), "{err}");
}
