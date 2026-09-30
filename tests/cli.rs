use assert_cmd::Command;

#[test]
fn version_flag_prints_semver() {
    Command::cargo_bin("amirustrained")
        .unwrap()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicates::str::contains("amirustrained 0.1.0"));
}
