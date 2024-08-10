# rs-merkletree
A Rust Library to generate Merkle Trees.


<a href="https://crates.io"><img src="https://img.shields.io/static/v1?label=crates.io&message=0.1.0&color=white&link=https://docs.rs" /></a> <a href="https://docs.rs"><img src="https://img.shields.io/static/v1?label=docs&message=passing&color=blue&link=https://docs.rs" /></a> <a href="https://docs.rs"><img src="https://img.shields.io/static/v1?label=Build and test&message=passing&color=lightgreen&link=https://docs.rs" /></a>

[![github](https://img.shields.io/badge/github-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/varun-doshi/rs-merkletree)
[![twitter](https://img.shields.io/badge/twitter-1DA1F2?style=for-the-badge&logo=twitter&logoColor=white)](https://twitter.com/Varunx10)


# About Merkle Trees
 In cryptography and computer science, a hash tree or Merkle tree is a tree in which every "leaf" node is labelled with the cryptographic hash of a data block, and every node that is not a leaf (called a branch, inner node, or inode) is labelled with the cryptographic hash of the labels of its child nodes. A hash tree allows efficient and secure verification of the contents of a large data structure.

Hash trees can be used to verify any kind of data stored, handled and transferred in and between computers. They can help ensure that data blocks received from other peers in a peer-to-peer network are received undamaged and unaltered, and even to check that the other peers do not lie and send fake blocks.

Hash trees are used in:

- Hash-based Cryptography
- InterPlanetary File System (IPFS)
- BitTorrent
- Btrfs and ZFS file systems
- Dat protocol
- Apache Wave protocol
- Zeronet
- Bitcoin and Ethereum peer-to-peer networks
## Usage

Add the following to your `cargo.toml` to start using `rs-merkletree`

```bash
  [dependencies]
  rs-merkletree = "0.1.0"
```
## Examples

Create a Merkle Tree and print the Root Hash
```bash
use rs_merkletree::MerkleTree;
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
```

For more examples, check out the official [docs](https://crates.io) or the `tests` folder

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this crate by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
