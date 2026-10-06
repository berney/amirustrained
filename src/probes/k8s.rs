use crate::model::{Fact, ProbeOutcome};
use crate::pipeline::Ctx;
use crate::probes::Probe;
use crate::sys::fs::PseudoFs;
use crate::sys::os::OsApi;

const PROBE: &str = "k8s";
const SA_DIR: &str = "/var/run/secrets/kubernetes.io/serviceaccount";

/// Pod names are `<name>-<hash>-<suffix>` where Kubernetes generates the
/// final 5-char suffix from consonants+digits only (vowels are excluded to
/// avoid profanity), giving a cheap distinctive signal for pod hostnames
/// like `nginx-6f8b7d9c4d-x2kq` or pod entries in `/etc/hosts`.
pub fn podish(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() >= 3
        && parts.iter().skip(1).any(|p| {
            p.len() == 5
                && p.chars()
                    .all(|c| "bcdfghjklmnpqrstvwxz0123456789".contains(c))
        })
}

/// Kubernetes-pod detection from inside the container, plus a cgroup-derived
/// QoS class. Every signal degrades to false/null: missing service-account
/// files, hostname files, or env vars never fail the probe. QoS can only be
/// inferred on unified cgroups (`guaranteed` is indistinguishable from a
/// bounded `burstable` from inside the pod), so any bounded limit reports
/// `burstable`, all-`max` reports `besteffort`, v1/unreadable reports null.
pub fn probe_k8s(fs: &PseudoFs, os: &dyn OsApi, cgroup_path: &str) -> ProbeOutcome {
    let mut o = ProbeOutcome::empty(PROBE);
    let env_host = os.env("KUBERNETES_SERVICE_HOST").is_some();
    let service_account =
        fs.exists(&format!("{SA_DIR}/ca.crt")) || fs.exists(&format!("{SA_DIR}/token"));
    let namespace = fs
        .read(&format!("{SA_DIR}/namespace"))
        .ok()
        .map(|s| s.trim().to_string());
    let hostname = fs.read("/etc/hostname").unwrap_or_default();
    let hosts = fs.read("/etc/hosts").unwrap_or_default();
    let in_pod = env_host
        || service_account
        || podish(hostname.trim())
        || hosts
            .lines()
            .any(|l| l.split_whitespace().nth(1).is_some_and(podish));
    let qos = if fs.read("/sys/fs/cgroup/cgroup.controllers").is_ok() {
        let bounded = ["memory.max", "pids.max"].iter().any(|k| {
            fs.read(&format!("/sys/fs/cgroup{cgroup_path}/{k}"))
                .map(|v| v.trim() != "max")
                .unwrap_or(false)
        });
        Some(if bounded { "burstable" } else { "besteffort" })
    } else {
        None
    };
    o = o.with_fact(Fact::ok(
        PROBE,
        "inPod",
        in_pod.into(),
        "env+sa+hostname heuristics".to_string(),
    ));
    o = o.with_fact(Fact::ok(
        PROBE,
        "namespace",
        namespace
            .map(|n| serde_json::json!(n))
            .unwrap_or(serde_json::Value::Null),
        format!("{SA_DIR}/namespace"),
    ));
    o = o.with_fact(Fact::ok(
        PROBE,
        "envHost",
        env_host.into(),
        "KUBERNETES_SERVICE_HOST".to_string(),
    ));
    o = o.with_fact(Fact::ok(
        PROBE,
        "serviceAccount",
        service_account.into(),
        SA_DIR.to_string(),
    ));
    o = o.with_fact(Fact::ok(
        PROBE,
        "qos",
        qos.map(|q| serde_json::json!(q))
            .unwrap_or(serde_json::Value::Null),
        "/sys/fs/cgroup limits".to_string(),
    ));
    o
}

pub struct K8s;

impl Probe for K8s {
    fn name(&self) -> &'static str {
        PROBE
    }
    fn run(&self, cx: &Ctx) -> ProbeOutcome {
        // Registry order guarantees the cgroup probe ran before k8s; when it
        // failed (no `cgroup.path` fact), QoS falls back to the root cgroup.
        let path = cx
            .prior
            .facts
            .get("cgroup.path")
            .and_then(|v| v.as_str())
            .unwrap_or("/")
            .to_string();
        probe_k8s(cx.fs, cx.os, &path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Env(&'static [(&'static str, &'static str)]);
    impl crate::sys::os::OsApi for Env {
        // signatures MUST match Task 4 trait
        fn hypervisor(&self) -> crate::sys::os::HypervisorInfo {
            Default::default()
        }
        fn landlock_abi(&self) -> Option<u64> {
            None
        }
        fn seccomp_actions(&self) -> crate::sys::os::SeccompActions {
            Default::default()
        }
        fn seccomp_filter_dump(&self, _p: u32) -> Result<Vec<u64>, crate::sys::fs::ProbeIo> {
            Err(crate::sys::fs::ProbeIo::PermissionDenied)
        }
        fn syscall0(&self, _n: u32) -> Result<(), i32> {
            Err(38)
        }
        fn uds_probe(
            &self,
            _p: &std::path::Path,
            _t: std::time::Duration,
        ) -> std::io::Result<crate::sys::os::UdsReply> {
            Err(std::io::Error::other("x"))
        }
        fn env(&self, k: &str) -> Option<String> {
            self.0
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| v.to_string())
        }
        fn is_root(&self) -> bool {
            false
        }
    }
    fn w(dir: &tempfile::TempDir, rel: &str, body: &str) {
        let f = dir.path().join(rel);
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(f, body).unwrap();
    }
    fn fact(o: &crate::model::ProbeOutcome, key: &str) -> serde_json::Value {
        o.facts
            .iter()
            .find(|f| f.key == key)
            .unwrap_or_else(|| panic!("missing fact {key}"))
            .value
            .clone()
    }

    #[test]
    fn pod_detected_env_and_sa() {
        let d = tempfile::tempdir().unwrap();
        w(
            &d,
            "var/run/secrets/kubernetes.io/serviceaccount/namespace",
            "prod\n",
        );
        w(&d, "etc/hostname", "nginx-7d9c-blue\n");
        w(&d, "etc/hosts", "10.42.0.7\tnextcloud-6f8b-pod\n");
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let os = Env(&[
            ("KUBERNETES_SERVICE_HOST", "10.43.0.1"),
            ("KUBERNETES_SERVICE_PORT", "443"),
        ]);
        let o = probe_k8s(&fs, &os, "/");
        assert_eq!(fact(&o, "inPod"), serde_json::json!(true));
        assert_eq!(fact(&o, "namespace"), "prod");
        assert_eq!(fact(&o, "envHost"), serde_json::json!(true));
    }

    #[test]
    fn not_in_pod() {
        let d = tempfile::tempdir().unwrap();
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let os = Env(&[]);
        let o = probe_k8s(&fs, &os, "/");
        assert_eq!(fact(&o, "inPod"), serde_json::json!(false));
        assert_eq!(fact(&o, "namespace"), serde_json::Value::Null);
        assert_eq!(fact(&o, "envHost"), serde_json::json!(false));
        assert_eq!(fact(&o, "serviceAccount"), serde_json::json!(false));
        assert_eq!(fact(&o, "qos"), serde_json::Value::Null);
    }

    #[test]
    fn podish_matches_pod_suffixes_only() {
        // live pod: <rs-name>-<rs-hash>-<5-char suffix>
        assert!(podish("api-7d9c4d8f5b-x2kq9"));
        assert!(podish("nextcloud-6f8b7d9c4d-b7ght"));
        // deployments, timestamps, ordinary hostnames: no vowel-free 5-part
        assert!(!podish("web-server"));
        assert!(!podish("build-abcde-1"));
        assert!(!podish("nginx-7d9c-blue"));
        assert!(!podish("host"));
    }

    #[test]
    fn pod_detected_by_sa_only_namespace_trimmed() {
        let d = tempfile::tempdir().unwrap();
        w(
            &d,
            "var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
            "PEM",
        );
        w(
            &d,
            "var/run/secrets/kubernetes.io/serviceaccount/namespace",
            "  kube-system \n",
        );
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let os = Env(&[]);
        let o = probe_k8s(&fs, &os, "/");
        assert_eq!(fact(&o, "inPod"), serde_json::json!(true));
        assert_eq!(fact(&o, "serviceAccount"), serde_json::json!(true));
        assert_eq!(fact(&o, "namespace"), "kube-system");
        assert_eq!(fact(&o, "envHost"), serde_json::json!(false));
    }

    #[test]
    fn pod_detected_by_hostname_when_token_present() {
        let d = tempfile::tempdir().unwrap();
        w(
            &d,
            "var/run/secrets/kubernetes.io/serviceaccount/token",
            "jwt",
        );
        w(&d, "etc/hostname", "api-7d9c4d8f5b-x2kq9\n");
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let os = Env(&[]);
        let o = probe_k8s(&fs, &os, "/");
        assert_eq!(fact(&o, "inPod"), serde_json::json!(true));
        // no namespace file ⇒ null, but the pod is still detected
        assert_eq!(fact(&o, "namespace"), serde_json::Value::Null);
    }

    #[test]
    fn qos_besteffort_when_all_limits_max() {
        let d = tempfile::tempdir().unwrap();
        w(&d, "sys/fs/cgroup/cgroup.controllers", "cpu memory pids\n");
        w(&d, "sys/fs/cgroup/memory.max", "max\n");
        w(&d, "sys/fs/cgroup/pids.max", "max\n");
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let os = Env(&[]);
        assert_eq!(fact(&probe_k8s(&fs, &os, "/"), "qos"), "besteffort");
    }

    #[test]
    fn qos_burstable_when_any_limit_bounded() {
        let d = tempfile::tempdir().unwrap();
        let cg = "kubepods.slice/kubepods-burstable.slice";
        w(&d, "sys/fs/cgroup/cgroup.controllers", "cpu memory pids\n");
        w(&d, &format!("sys/fs/cgroup/{cg}/memory.max"), "104857600\n");
        w(&d, &format!("sys/fs/cgroup/{cg}/pids.max"), "max\n");
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let os = Env(&[]);
        assert_eq!(
            fact(&probe_k8s(&fs, &os, &format!("/{cg}")), "qos"),
            "burstable"
        );
        // limits absent at the probed path count as unbounded ⇒ besteffort
        assert_eq!(fact(&probe_k8s(&fs, &os, "/"), "qos"), "besteffort");
    }

    #[test]
    fn qos_null_on_v1_or_unreadable_cgroup() {
        let d = tempfile::tempdir().unwrap();
        // no cgroup.controllers file: v1 or unreadable ⇒ null, never an error
        w(&d, "sys/fs/cgroup/memory/memory.limit_in_bytes", "max\n");
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let os = Env(&[]);
        assert_eq!(
            fact(&probe_k8s(&fs, &os, "/"), "qos"),
            serde_json::Value::Null
        );
    }

    #[test]
    fn run_consumes_prior_cgroup_path() {
        let d = tempfile::tempdir().unwrap();
        let cg = "kubepods.slice/kubepods-besteffort.slice";
        w(&d, "sys/fs/cgroup/cgroup.controllers", "cpu memory pids\n");
        w(&d, &format!("sys/fs/cgroup/{cg}/memory.max"), "2097152\n");
        w(&d, "etc/hostname", "api-7d9c4d8f5b-x2kq9\n");
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let os = Env(&[]);
        let opts = crate::opts::Opts {
            pid: None,
            probe_syscalls: false,
            probe_kernel_execution: false,
            probe_device_open: false,
            compact: false,
            probe_ebpf: Vec::new(),
            dump_filters: false,
            probe_timeout: None,
            fail_on: None,
        };
        let mut facts = std::collections::HashMap::new();
        facts.insert(
            "cgroup.path".to_string(),
            serde_json::json!(format!("/{cg}")),
        );
        let cx = crate::pipeline::Ctx {
            pid: 4242,
            uid: 1000,
            fs: &fs,
            os: &os,
            opts: &opts,
            prior: crate::pipeline::Prior {
                signals: vec![],
                facts,
            },
        };
        let o = K8s.run(&cx);
        assert_eq!(o.name, "k8s");
        assert_eq!(fact(&o, "qos"), "burstable");
        assert_eq!(fact(&o, "inPod"), serde_json::json!(true));
    }

    #[test]
    fn run_without_prior_cgroup_path_defaults_to_root() {
        let d = tempfile::tempdir().unwrap();
        w(&d, "sys/fs/cgroup/cgroup.controllers", "cpu memory pids\n");
        w(&d, "sys/fs/cgroup/memory.max", "max\n");
        w(&d, "sys/fs/cgroup/pids.max", "max\n");
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let os = Env(&[]);
        let opts = crate::opts::Opts {
            pid: None,
            probe_syscalls: false,
            probe_kernel_execution: false,
            probe_device_open: false,
            compact: false,
            probe_ebpf: Vec::new(),
            dump_filters: false,
            probe_timeout: None,
            fail_on: None,
        };
        let cx = crate::pipeline::Ctx {
            pid: 1,
            uid: 0,
            fs: &fs,
            os: &os,
            opts: &opts,
            prior: crate::pipeline::Prior::default(),
        };
        assert_eq!(fact(&K8s.run(&cx), "qos"), "besteffort");
    }
}
