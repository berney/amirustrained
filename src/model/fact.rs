use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FactStatus {
    Ok,
    Unavailable,
    Degraded,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Fact {
    pub probe: String,
    pub key: String,
    pub value: Value,
    pub source: String,
    pub status: FactStatus,
}

impl Fact {
    pub fn ok(probe: &str, key: &str, value: Value, source: String) -> Self {
        Self {
            probe: probe.into(),
            key: key.into(),
            value,
            source,
            status: FactStatus::Ok,
        }
    }
    pub fn degraded(probe: &str, key: &str, value: Value, source: String) -> Self {
        Self {
            probe: probe.into(),
            key: key.into(),
            value,
            source,
            status: FactStatus::Degraded,
        }
    }
    pub fn unavailable(probe: &str, key: &str, source: String, errno: Option<i32>) -> Self {
        Self {
            probe: probe.into(),
            key: key.into(),
            source,
            value: serde_json::json!({ "unavailable": true, "errno": errno }),
            status: FactStatus::Unavailable,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fact_serde_shape() {
        let f = Fact::ok(
            "uidmap",
            "rootless",
            serde_json::json!(true),
            "/proc/1/uid_map".into(),
        );
        let j = serde_json::to_string(&f).unwrap();
        assert_eq!(
            j,
            r#"{"probe":"uidmap","key":"rootless","value":true,"source":"/proc/1/uid_map","status":"ok"}"#
        );
    }
    #[test]
    fn unavailable_carries_errno() {
        let f = Fact::unavailable(
            "lsm",
            "lockdown",
            "/sys/kernel/security/lockdown".into(),
            Some(2),
        );
        assert_eq!(f.status, FactStatus::Unavailable);
        assert_eq!(f.value["errno"], 2);
    }
}
