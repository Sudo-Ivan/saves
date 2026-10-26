// SPDX-License-Identifier: 0BSD

use saves_sdk::*;

#[test]
fn roundtrip() {
    let url = match std::env::var("SAVES_URL") {
        Ok(u) => u,
        Err(_) => {
            eprintln!("skipped: SAVES_URL unset");
            return;
        }
    };
    let tok = std::env::var("SAVES_TOKEN").unwrap();
    let c = Client::new(&url, &tok);
    let me = c.me().unwrap();
    assert!(me["user"]["id"].is_string() || me["user"].is_object());
    // push a dir
    let dir = std::env::temp_dir().join(format!("sdk-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("empty")).unwrap();
    std::fs::write(dir.join("hello.txt"), b"hi").unwrap();
    let big = vec![7u8; 3 << 20];
    std::fs::write(dir.join("big.bin"), &big).unwrap();
    let opts = PushOptions {
        root: "save".into(),
        device: "test".into(),
        ..Default::default()
    };
    let head = c.push("sdk-test", "saves", &dir, &opts).unwrap();
    assert!(!head.is_empty());
    // pull
    let out = std::env::temp_dir().join(format!("sdk-out-{}", std::process::id()));
    std::fs::create_dir_all(&out).unwrap();
    c.pull("sdk-test", "saves", &head, &out, &PullOptions::default())
        .unwrap();
    assert_eq!(std::fs::read(out.join("save/hello.txt")).unwrap(), b"hi");
    assert_eq!(std::fs::read(out.join("save/big.bin")).unwrap(), big);
    assert!(out.join("save/empty").is_dir());
    // stale head conflict
    let err = c.commit_snapshot("sdk-test", "saves", &head, "stale-head-id", false);
    assert!(err.is_err());
    // tokens
    let t = c.create_token("sdk", &["read"]).unwrap();
    c.patch_token(
        t["id"].as_str().unwrap(),
        &serde_json::json!({"name": "sdk2"}),
    )
    .unwrap();
    c.revoke_token(t["id"].as_str().unwrap()).unwrap();
    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_dir_all(&out).ok();
}
