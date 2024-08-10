#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use rs_merkletree::MerkleTree;

    #[test]
    fn it_works() {
        let data: Vec<&str> = vec!["Hello", "World", "From", "Rust"];
        let mut tree = MerkleTree::new(None);
        let rootNode = tree.build_tree(data);
        let root_hash = rootNode.root_node().unwrap().hash();
        assert_eq!(
            String::from_utf8(root_hash),
            Ok(String::from(
                "725367a8cee028cf3360c19d20c175733191562b01e60d093e81d8570e865f81"
            ))
        );

        let path = tree.includes(
            "d9aa89fdd15ad5c41d9c128feffe9e07dc828b83f85296f7f42bda506821300e".as_bytes(),
        );
        assert_eq!(path, true);

        println!("Depth:{}",tree.depth());

        println!("Leaves:{}",tree.count_leaves());
    }
}
