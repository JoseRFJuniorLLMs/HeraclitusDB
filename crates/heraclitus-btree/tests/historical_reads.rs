use heraclitus_btree::BEpsilonTree;

#[test]
fn historical_generations_never_return_the_current_leaf() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("tree.db");
    let mut tree = BEpsilonTree::open(&path, 16, 16).unwrap();
    tree.upsert(b"key".to_vec(), b"old".to_vec()).unwrap();
    tree.commit().unwrap();
    tree.upsert(b"key".to_vec(), b"new".to_vec()).unwrap();
    tree.commit().unwrap();
    assert_eq!(
        tree.get_snapshot(b"key", 1).unwrap_err().kind(),
        std::io::ErrorKind::Unsupported
    );
    assert_eq!(
        tree.get_snapshot(b"key", u64::MAX).unwrap(),
        Some(b"new".to_vec())
    );
    drop(tree);
    let tree = BEpsilonTree::open(&path, 16, 16).unwrap();
    assert_eq!(
        tree.get_snapshot(b"key", 1).unwrap_err().kind(),
        std::io::ErrorKind::Unsupported
    );
    assert_eq!(tree.get(b"key"), Some(b"new".to_vec()));
}
