use serde::Serialize;
use std::collections::HashMap;

use super::Probe;
use crate::model::{Fact, ProbeOutcome, RuntimeKind, Signal};
use crate::pipeline::Ctx;
use crate::sys::fs::{PseudoFs, errno_of};

/// One line of `/proc/<pid>/uid_map` (or `gid_map`): `container host range`.
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub struct MapRow {
    pub container: u32,
    pub host: u32,
    pub range: u32,
}

/// Parses a uid_map/gid_map body. Whitespace-flexible; blank or malformed
/// lines are skipped rather than failing the whole map.
pub fn parse_map(s: &str) -> Vec<MapRow> {
    s.lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            Some(MapRow {
                container: it.next()?.parse().ok()?,
                host: it.next()?.parse().ok()?,
                range: it.next()?.parse().ok()?,
            })
        })
        .collect()
}

/// Parses Uid, Gid, and Groups from `/proc/<pid>/status`.
pub fn parse_status_ids(status: &str) -> (Option<u32>, Option<u32>, Vec<u32>) {
    let mut uid = None;
    let mut gid = None;
    let mut groups = Vec::new();
    for line in status.lines() {
        let mut it = line.splitn(2, ':');
        let (k, v) = (it.next().unwrap_or(""), it.next().unwrap_or("").trim());
        match k {
            "Uid" => {
                let parts: Vec<&str> = v.split_whitespace().collect();
                uid = parts
                    .get(1)
                    .or_else(|| parts.first())
                    .and_then(|s| s.parse().ok());
            }
            "Gid" => {
                let parts: Vec<&str> = v.split_whitespace().collect();
                gid = parts
                    .get(1)
                    .or_else(|| parts.first())
                    .and_then(|s| s.parse().ok());
            }
            "Groups" => {
                groups = v
                    .split_whitespace()
                    .filter_map(|s| s.parse::<u32>().ok())
                    .collect();
            }
            _ => {}
        }
    }
    (uid, gid, groups)
}

/// Parses `/etc/group` lines into a GID -> group name map.
pub fn parse_etc_group(content: &str) -> HashMap<u32, String> {
    let mut map = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 3 {
            let name = parts[0].trim();
            if let Ok(gid) = parts[2].trim().parse::<u32>() {
                map.insert(gid, name.to_string());
            }
        }
    }
    map
}

/// Parses `/etc/passwd` lines into a UID -> (username, Option<full_name>) map.
pub fn parse_etc_passwd_full(content: &str) -> HashMap<u32, (String, Option<String>)> {
    let mut map = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 3 {
            let name = parts[0].trim().to_string();
            let full_name = if parts.len() >= 5 {
                let gecos = parts[4].split(',').next().unwrap_or("").trim();
                if gecos.is_empty() {
                    None
                } else {
                    Some(gecos.to_string())
                }
            } else {
                None
            };
            if let Ok(uid) = parts[2].trim().parse::<u32>() {
                map.insert(uid, (name, full_name));
            }
        }
    }
    map
}

/// Parses `/etc/passwd` lines into a UID -> user name map.
pub fn parse_etc_passwd(content: &str) -> HashMap<u32, String> {
    let mut map = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 3 {
            let name = parts[0].trim();
            if let Ok(uid) = parts[2].trim().parse::<u32>() {
                map.insert(uid, name.to_string());
            }
        }
    }
    map
}

pub fn probe_uidmap(fs: &PseudoFs, pid: u32) -> ProbeOutcome {
    let mut o = ProbeOutcome::empty("uidmap");
    let base = format!("/proc/{pid}");
    let mut rootless = false;
    for (key, file) in [("uidMap", "uid_map"), ("gidMap", "gid_map")] {
        match fs.read(&format!("{base}/{file}")) {
            Ok(s) => {
                let rows = parse_map(&s);
                if key == "uidMap" {
                    rootless = rows.len() == 1
                        && rows[0].container == 0
                        && rows[0].host != 0
                        && rows[0].range < u32::MAX;
                }
                o = o.with_fact(Fact::ok(
                    "uidmap",
                    key,
                    serde_json::to_value(&rows).unwrap(),
                    format!("{base}/{file}"),
                ));
            }
            Err(e) => {
                o = o.with_fact(Fact::unavailable(
                    "uidmap",
                    key,
                    format!("{base}/{file}"),
                    errno_of(&e),
                ));
            }
        }
    }
    match fs.read(&format!("{base}/setgroups")) {
        Ok(s) => {
            o = o.with_fact(Fact::ok(
                "uidmap",
                "setgroups",
                s.into(),
                format!("{base}/setgroups"),
            ))
        }
        // setgroups absent ⇒ pre-3.19 kernel or EACCES inside container: absent-safe.
        Err(_) => {
            o = o.with_fact(Fact::degraded(
                "uidmap",
                "setgroups",
                serde_json::Value::Null,
                format!("{base}/setgroups"),
            ))
        }
    }
    let rf = Fact::ok(
        "uidmap",
        "rootless",
        rootless.into(),
        format!("{base}/uid_map"),
    );
    if rootless {
        // A user's rootless uidmap layout describes the environment, not the
        // scanning process's containment: env-only note, never a score
        // (spec §5 amendment 2026-10-01).
        o = o.with_signal(Signal {
            runtime: RuntimeKind::Podman,
            weight: 0.3,
            evidence: rf.clone(),
            env_only: true,
        });
    }
    o = o.with_fact(rf);
    let status_src = format!("{base}/status");
    match fs.read(&status_src) {
        Ok(status) => {
            let (uid_opt, gid_opt, groups) = parse_status_ids(&status);
            let group_map = fs
                .read("/etc/group")
                .ok()
                .map(|s| parse_etc_group(&s))
                .unwrap_or_default();
            let user_map = fs
                .read("/etc/passwd")
                .ok()
                .map(|s| parse_etc_passwd(&s))
                .unwrap_or_default();

            let uid = uid_opt.unwrap_or(0);
            let gid = gid_opt.unwrap_or(0);

            let user_name = user_map.get(&uid).cloned().unwrap_or_else(|| {
                if uid == 0 {
                    "root".to_string()
                } else {
                    "unknown".to_string()
                }
            });
            let group_name = group_map.get(&gid).cloned().unwrap_or_else(|| {
                if gid == 0 {
                    "root".to_string()
                } else {
                    "unknown".to_string()
                }
            });

            let groups_resolved: Vec<String> = groups
                .iter()
                .map(|g| {
                    let gname = group_map.get(g).cloned().unwrap_or_else(|| {
                        if *g == 0 {
                            "root".to_string()
                        } else {
                            "unknown".to_string()
                        }
                    });
                    format!("{g}({gname})")
                })
                .collect();

            let groups_str = groups_resolved.join(",");

            o = o.with_fact(Fact::ok(
                "uidmap",
                "uid",
                serde_json::json!(uid),
                status_src.clone(),
            ));
            o = o.with_fact(Fact::ok(
                "uidmap",
                "user",
                serde_json::json!(user_name),
                "/etc/passwd".into(),
            ));
            o = o.with_fact(Fact::ok(
                "uidmap",
                "gid",
                serde_json::json!(gid),
                status_src.clone(),
            ));
            o = o.with_fact(Fact::ok(
                "uidmap",
                "group",
                serde_json::json!(group_name),
                "/etc/group".into(),
            ));
            o = o.with_fact(Fact::ok(
                "uidmap",
                "groups",
                serde_json::json!(groups_resolved),
                status_src.clone(),
            ));
            o = o.with_fact(Fact::ok(
                "uidmap",
                "groupsFormatted",
                serde_json::json!(groups_str),
                status_src,
            ));
        }
        Err(e) => {
            let errno = errno_of(&e);
            for key in ["uid", "user", "gid", "group", "groups", "groupsFormatted"] {
                o = o.with_fact(Fact::unavailable("uidmap", key, status_src.clone(), errno));
            }
        }
    }
    o
}

pub struct Uidmap;

impl Probe for Uidmap {
    fn name(&self) -> &'static str {
        "uidmap"
    }
    fn run(&self, cx: &Ctx) -> ProbeOutcome {
        probe_uidmap(cx.fs, cx.pid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::FactStatus;
    fn fixture(files: &[(&str, &str)]) -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        for (p, c) in files {
            let full = d.path().join(p.trim_start_matches('/'));
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, c).unwrap();
        }
        d
    }
    #[test]
    fn rootless_single_mapped_row() {
        let d = fixture(&[
            ("proc/42/uid_map", "         0       100000      65536\n"),
            ("proc/42/gid_map", "         0       100000      65536\n"),
            ("proc/42/setgroups", "deny\n"),
        ]);
        let rows = parse_map("0 100000 65536");
        assert_eq!(
            rows[0],
            MapRow {
                container: 0,
                host: 100000,
                range: 65536
            }
        );
        // drive the probe via public helper used in run():
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let outcome = probe_uidmap(&fs, 42);
        assert!(
            outcome
                .facts
                .iter()
                .any(|f| f.key == "rootless" && f.value == serde_json::json!(true))
        );
        assert!(
            outcome
                .facts
                .iter()
                .any(|f| f.key == "setgroups" && f.value == "deny")
        );
    }
    #[test]
    fn identity_map_is_not_rootless() {
        let d = fixture(&[("proc/42/uid_map", "         0          0 4294967295\n")]);
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let o = probe_uidmap(&fs, 42);
        assert!(
            o.facts
                .iter()
                .any(|f| f.key == "rootless" && f.value == serde_json::json!(false))
        );
    }

    #[test]
    fn parse_map_handles_multi_rows_and_trailing_whitespace() {
        let rows = parse_map(
            "         0          0          1 \n         1       1000       1\n   \n65534 65534 1\t",
        );
        assert_eq!(
            rows,
            vec![
                MapRow {
                    container: 0,
                    host: 0,
                    range: 1
                },
                MapRow {
                    container: 1,
                    host: 1000,
                    range: 1
                },
                MapRow {
                    container: 65534,
                    host: 65534,
                    range: 1
                },
            ]
        );
        // Full `nobody` range fits u32 exactly.
        assert_eq!(parse_map("0 0 4294967295")[0].range, u32::MAX);
    }

    #[test]
    fn rootless_emits_podman_signal_with_expected_fact_shape() {
        let d = fixture(&[
            ("proc/42/uid_map", "         0       100000      65536\n"),
            ("proc/42/gid_map", "         0       100000      65536\n"),
            ("proc/42/setgroups", "deny\n"),
        ]);
        let o = probe_uidmap(&crate::sys::fs::PseudoFs::new(d.path().into()), 42);
        assert_eq!(o.name, "uidmap");
        assert_eq!(
            o.signals.len(),
            1,
            "exactly one rootless signal: {:?}",
            o.signals
                .iter()
                .map(|s| (s.runtime, s.weight))
                .collect::<Vec<_>>()
        );
        assert!(matches!(o.signals[0].runtime, RuntimeKind::Podman));
        assert_eq!(o.signals[0].weight, 0.3);
        assert_eq!(o.signals[0].evidence.key, "rootless");
        assert_eq!(o.signals[0].evidence.status, FactStatus::Ok);
        assert!(
            o.signals[0].env_only,
            "a rootless uidmap is a user's environment layout, not containment"
        );
        let um = o.facts.iter().find(|f| f.key == "uidMap").unwrap();
        assert_eq!(um.source, "/proc/42/uid_map");
        assert_eq!(
            um.value,
            serde_json::json!([{"container": 0, "host": 100000, "range": 65536}])
        );
        let sg = o.facts.iter().find(|f| f.key == "setgroups").unwrap();
        assert_eq!(sg.value, serde_json::json!("deny"));
    }

    #[test]
    fn absent_files_degrade_per_the_error_table() {
        let d = fixture(&[]);
        let o = probe_uidmap(&crate::sys::fs::PseudoFs::new(d.path().into()), 9);
        for key in ["uidMap", "gidMap"] {
            let f = o.facts.iter().find(|f| f.key == key).unwrap();
            assert_eq!(
                f.status,
                FactStatus::Unavailable,
                "{key} should be unavailable"
            );
            assert_eq!(f.value["errno"], 2, "{key} should report ENOENT");
        }
        let sg = o.facts.iter().find(|f| f.key == "setgroups").unwrap();
        assert_eq!(sg.status, FactStatus::Degraded);
        assert_eq!(sg.value, serde_json::Value::Null);
        assert!(
            o.facts
                .iter()
                .any(|f| f.key == "rootless" && f.value == serde_json::json!(false))
        );
        assert!(o.signals.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn live_host_smoke_is_structurally_wellformed() {
        // Structural shape only: never assert the host's actual mapping values.
        let o = probe_uidmap(&crate::sys::fs::PseudoFs::real(), std::process::id());
        assert_eq!(o.name, "uidmap");
        assert_eq!(o.facts.len(), 10);
        assert!(o.facts.iter().all(|f| f.probe == "uidmap"));
        for key in [
            "uidMap",
            "gidMap",
            "setgroups",
            "rootless",
            "uid",
            "user",
            "gid",
            "group",
            "groups",
            "groupsFormatted",
        ] {
            assert!(o.facts.iter().any(|f| f.key == key), "missing fact {key}");
        }
        let rootless = o.facts.iter().find(|f| f.key == "rootless").unwrap();
        assert!(rootless.value.is_boolean());
        if let Some(um) = o.facts.iter().find(|f| f.key == "uidMap")
            && um.status == FactStatus::Ok
        {
            assert!(um.value.is_array());
        }
    }

    #[test]
    fn status_and_groups_resolution() {
        let status =
            "Uid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nGroups:\t0 10 998\n";
        let group_file = "root:x:0:\nwheel:x:10:user\ndocker:x:998:user\n";
        let passwd_file =
            "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000:user:/home/user:/bin/bash\n";
        let d = fixture(&[
            ("proc/42/status", status),
            ("etc/group", group_file),
            ("etc/passwd", passwd_file),
        ]);
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let o = probe_uidmap(&fs, 42);
        assert_eq!(o.facts.iter().find(|f| f.key == "uid").unwrap().value, 1000);
        assert_eq!(
            o.facts.iter().find(|f| f.key == "user").unwrap().value,
            "user"
        );
        assert_eq!(o.facts.iter().find(|f| f.key == "gid").unwrap().value, 1000);
        assert_eq!(
            o.facts.iter().find(|f| f.key == "group").unwrap().value,
            "unknown"
        );
        assert_eq!(
            o.facts.iter().find(|f| f.key == "groups").unwrap().value,
            serde_json::json!(["0(root)", "10(wheel)", "998(docker)"])
        );
        assert_eq!(
            o.facts
                .iter()
                .find(|f| f.key == "groupsFormatted")
                .unwrap()
                .value,
            "0(root),10(wheel),998(docker)"
        );
    }
}
