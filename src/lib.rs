//! # rs-merkletree
//!
//! `rs-merkletree` is a Rust library to create Merkle trees.It allows creation of Merkle Trees using an [Vec](https://doc.rust-lang.org/std/vec/struct.Vec.html) of data. It is possible to check whether a certain hash is included in the tree. 
//! Currently, supports merklization from a Vec of [&str](https://doc.rust-lang.org/std/primitive.str.html).
//! 
//! 
//! # About Merkle Trees
//! In cryptography and computer science, a hash tree or Merkle tree is a tree in which every "leaf" node is labelled with the cryptographic hash of a data block, and every node that is not a leaf (called a branch, inner node, or inode) is labelled with the cryptographic hash of the labels of its child nodes. A hash tree allows efficient and secure verification of the contents of a large data structure.
//! 
//! 
//! # Examples
//! 
//! Create a Merkle Tree and print the Root Hash
//! ```
//! use rs_merkletree::MerkleTree;
//! let data: Vec<&str> = vec!["Hello", "World", "From", "Rust"];
//! let mut tree = MerkleTree::new(None);
//! let rootNode = tree.build_tree(data);
//! let root_hash = rootNode.root_node().unwrap().hash();
//! assert_eq!(
//!     String::from_utf8(root_hash),
//!     Ok(String::from(
//!         "725367a8cee028cf3360c19d20c175733191562b01e60d093e81d8570e865f81"
//!     ))
//! );
//! ```
//! 
//! Check inclusion of a hash in a Merkle Tree
//! ```
//! use rs_merkletree::MerkleTree;
//! let data: Vec<&str> = vec!["Hello", "World", "From", "Rust"];
//! let mut tree = MerkleTree::new(None);
//! let rootNode = tree.build_tree(data);
//! let root_hash = rootNode.root_node().unwrap().hash();
//! assert_eq!(
//!     String::from_utf8(root_hash),
//!     Ok(String::from(
//!         "725367a8cee028cf3360c19d20c175733191562b01e60d093e81d8570e865f81"
//!     ))
//! );
//! let path = tree.includes(
//! "d9aa89fdd15ad5c41d9c128feffe9e07dc828b83f85296f7f42bda506821300e".as_bytes(),
//! );
//! println!("{}",path);
//! ```

#![allow(non_snake_case)]

use crypto::{digest::Digest, sha2::Sha256};
use std::collections::VecDeque;





/// [MerkleTree](struct.MerkleTree.html) is the primary struct to hold Merkle Tree.
/// 
/// This is the main struct which cotains public functions to build the Merkle Tree from user data. It also contains functions to check for inclusion of a specific hash value.
/// # Examples
///
/// ```
/// use rs_merkletree::MerkleTree;
/// let data: Vec<&str> = vec!["Hello", "World", "From", "Rust"];
/// let mut tree = MerkleTree::new(None);
/// let rootNode = tree.build_tree(data);
/// let root_hash = rootNode.root_node().unwrap().hash();
/// 
/// assert_eq!(String::from_utf8(root_hash), 
///        Ok(String::from("725367a8cee028cf3360c19d20c175733191562b01e60d093e81d8570e865f81"))
///   );
/// ```
#[derive(Debug, Clone)]
pub struct MerkleTree {
    root_node: Option<Box<Node>>,
}

/// [Node](struct.Node.html) is the struct to hold each node of the Merkle Tree.
///
/// * `left_node`: Holds node of the left child. Can be `None` if it does not have a left child or is a leaf node.
///
/// * `right_node`: Holds node of the right child. Can be `None` if it does not have a left child or is a leaf node.
///
/// * `hash`: Contains the hash content of the node. Formulated as Hash(left_node.hash,right_node.hash)
#[derive(Debug, Clone,PartialEq)]
pub struct Node {
    left_node: Option<Box<Node>>,
    right_node: Option<Box<Node>>,
    hash: Vec<u8>,
}

impl Node {

    /// Function to create new instance of [Node](struct.Node.html).
    /// 
    /// Accepts: Hash, Optional leftNode, Optional rightNode.
    /// 
    /// Return type [Node](struct.Node.html)
    pub fn new(hash: Vec<u8>, leftNode: Option<Box<Node>>, rightNode: Option<Box<Node>>) -> Node {
        return Node {
            left_node: leftNode,
            right_node: rightNode,
            hash,
        };
    }
    /// Returns the Left Child of the Current Node which is of type [Node](struct.Node.html). Returns `None` if left child does note exist.
    pub fn left_node(&self) -> Option<Node> {
        let root_node = &self.left_node;
        match root_node {
            Some(node) => return Some(*node.left_node.clone().unwrap()),
            None => return None,
        }
    }
    
    /// Returns the Right Child of the Current Node which is of type [Node](struct.Node.html). Returns `None` if right child does note exist.
    pub fn right_node(&self) -> Option<Node> {
        let root_node = &self.right_node;
        match root_node {
            Some(node) => return Some(*node.right_node.clone().unwrap()),
            None => return None,
        }
    }

    /// Return the Hash Value of the current [Node](struct.Node.html) as type `Vec<u8>`
    pub fn hash(&self) -> Vec<u8> {
        let hash = &self.hash;
        return hash.to_vec();
    }


    pub fn depth(&self)->usize{
        let left_depth = self.left_node.as_ref().map_or(0, |node| node.depth());
        let right_depth = self.right_node.as_ref().map_or(0, |node| node.depth());

        // The depth is the maximum depth of the subtrees plus one for the current node
        usize::max(left_depth, right_depth) + 1

    }
}

impl MerkleTree {
    /// Function to build a new instance of [MerkleTree](struct.MerkleTree.html)
    /// ```
    /// use rs_merkletree::MerkleTree;
    /// let mut tree = MerkleTree::new(None);
    /// ```
    pub fn new(rootNode: Option<Box<Node>>) -> MerkleTree {
        println!("Building Merkle Tree");
        return MerkleTree {
            root_node: rootNode,
        };
    }

    /// Returns the `RootNode` which is of type [Node](struct.Node.html)
    /// 
    /// Returns `None` if the `RootNode` does not exist
    pub fn root_node(&self) -> Option<Node> {
        let root = &self.root_node;
        match root {
            Some(node) => return Some(*node.clone()),
            None => return None,
        }
    }

    /// Helper function to build the first layer of nodes.
    /// 
    /// This involves taking in the data provided by user and converting it to the respective hashes and form the leaf nodes of the merkle tree
    fn build_leaves(&self, data: Vec<&str>) -> Vec<Node> {
        let size = data.len();
        let mut ground_layer: Vec<Node> = Vec::new();
        let mut i = 0;
        while i < size {
            let current_hash = self.hasher_leaf(data[i]);
            let current_node = Node::new(current_hash, None, None);
            ground_layer.push(current_node);
            i += 1;
        }
        ground_layer
    }

    ///Function to hash leaf data.
    /// Specific to leaf nodes as they are always singluar data hashes.
    fn hasher_leaf(&self, data: &str) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.input(data.as_bytes());
        let hash: Vec<u8> = hasher.result_str().as_bytes().to_vec();
        return hash;
    }

    ///Function to hash any level other than the leaf.
    fn hasher_nodes(&self, left_data: Vec<u8>, right_data: Vec<u8>) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.input(left_data.as_slice());
        hasher.input(right_data.as_slice());
        let hash = hasher.result_str().as_bytes().to_vec();
        hash
    }

    ///Helper function to build the intermediate levels between the root and the leaves
    fn build_upper_layer(&self, leaves: Vec<Node>) -> Vec<Node> {
        let level = leaves.len();
        let mut layer: Vec<Node> = Vec::new();

        let mut i = 0;
        while i < level {
            if i + 1 >= level {
                let current_hash =
                    self.hasher_nodes(leaves[i].hash.clone(), leaves[i].hash.clone());

                let current_node = Node::new(current_hash, Some(Box::new(leaves[i].clone())), None);
                layer.push(current_node);
                i = i + 1;
            } else {
                let current_hash =
                    self.hasher_nodes(leaves[i].hash.clone(), leaves[i + 1].hash.clone());

                let current_node = Node::new(
                    current_hash,
                    Some(Box::new(leaves[i].clone())),
                    Some(Box::new(leaves[i + 1].clone())),
                );
                layer.push(current_node);
                i = i + 2;
            }
        }
        let size = layer.len();
        for j in 0..size {
            println!(
                "After build_upper_layer: {:?}",
                String::from_utf8(layer[j].hash.clone())
            );
        }
        layer
    }

    ///Helper function to build the root node
    fn build_root(&self, leftNode: Node, rightNode: Node) -> Node {
        println!(
            "Root left values being hashed:{:?}",
            String::from_utf8(leftNode.clone().hash)
        );
        println!(
            "Root left values being hashed:{:?}",
            String::from_utf8(rightNode.clone().hash)
        );
        let hash = self.hasher_nodes(leftNode.clone().hash, rightNode.clone().hash);
        return Node {
            left_node: Some(Box::new(leftNode)),
            right_node: Some(Box::new(rightNode)),
            hash: hash,
        };
    }

    ///Main Function to build the Merkle Tree
    /// 
    /// Parameters are the direct data provided by user. currently accepts `Vec<&str>` as input.
    /// Returns type [MerkleTree](struct.MerkleTree.html)
    pub fn build_tree(&mut self, data: Vec<&str>) -> &MerkleTree {
        let mut leaves: Vec<Node> = self.build_leaves(data);

        for i in 0..leaves.len() {
            println!("Leaf Value:{:?}", String::from_utf8(leaves[i].hash.clone()));
        }

        let upper_layer = self.build_upper_layer(leaves.clone());
        let mut size = upper_layer.len();
        leaves.extend(upper_layer.clone());
        // println!("Size:{}", size);

        if size == 1 {
            let root_node = leaves.pop().unwrap();
            let root = Node::new(root_node.hash, root_node.left_node, root_node.right_node);
            self.root_node = Some(Box::new(root));
            return self;
        }
        while size > 2 {
            let upper_layer = self.build_upper_layer(upper_layer.clone());
            size = upper_layer.len();
            leaves.extend(upper_layer);
        }
        let root = self.build_root(
            leaves[leaves.len() - 2].clone(),
            leaves[leaves.len() - 1].clone(),
        );
        // leaves.push(root);
        println!("Final Tree: ");
        for j in 0..leaves.len() {
            println!("{:?}", String::from_utf8(leaves[j].clone().hash));
        }
        self.root_node = Some(Box::new(root));
        return self;
    }

    
    //Function to get the depth of the Tree
    /// 
    /// Returns the depth of the tree from the Root Node to the leaf as [usize](https://doc.rust-lang.org/std/primitive.usize.html)
    pub fn depth(&self)->usize{
        self.root_node().unwrap().depth()
    }

    ///Function to get the number of leaves in the tree
    /// 
    /// Returns the number of leaves in the tree as [usize](https://doc.rust-lang.org/std/primitive.usize.html)
    pub fn count_leaves(&self)->usize{
        let mut count=0;
        let mut data_array = VecDeque::new();
        if let Some(ref root) = self.root_node {
            data_array.push_front(root.as_ref());
        }
        while let Some(node) = data_array.pop_front() {
            match (&node.left_node, &node.right_node) {
                (None, None) => {
                    count += 1; // It's a leaf node
                }
                (Some(left), Some(right)) => {
                    data_array.push_back(right.as_ref());
                    data_array.push_back(left.as_ref());
                }
                (Some(left), None) => {
                    data_array.push_back(left.as_ref());
                }
                (None, Some(right)) => {
                    data_array.push_back(right.as_ref());
                }
            }
        }
    
        count
    }
    
    ///Function to check whether a specififc hash is present in the tree.  Returns `True` if hash is present, else `False`.
    ///
    /// Note: Input parameter should be a hash; not the actual string
    pub fn includes(&self, data: &[u8]) -> bool {
        let mut data_array = VecDeque::new();
        data_array.push_front(self.root_node.clone());
        while data_array.len() > 0 {
            let element = data_array.pop_front().unwrap();
            // println!("ELement in include func:{:?}", element);

            if element.clone().unwrap().hash == data {
                return true;
            } else {
                if element.clone().unwrap().right_node.is_some() {
                    data_array.push_front(element.clone().unwrap().right_node);
                }
                if element.clone().unwrap().left_node.is_some() {
                    data_array.push_front(element.clone().unwrap().left_node);
                }
            }
        }

        false
    }
}
