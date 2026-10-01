use std::{fs, path::Path};

#[test]
fn production_sources_remain_reviewably_small() {
    visit(Path::new("src"));
    visit(Path::new("tests"));
}

fn visit(path: &Path) {
    for entry in fs::read_dir(path).expect("source directory") {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            visit(&path);
        } else if path.extension().and_then(|value| value.to_str()) == Some("rs") {
            let source = fs::read_to_string(&path).expect("source");
            let count = source
                .lines()
                .filter(|line| {
                    let value = line.trim();
                    !value.is_empty() && !value.starts_with("//")
                })
                .count();
            assert!(
                count < 150,
                "{} has {count} non-comment lines",
                path.display()
            );
        }
    }
}
