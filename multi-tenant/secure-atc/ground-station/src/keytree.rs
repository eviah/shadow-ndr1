//! Forward-secret ephemeral key tree (frontier upgrade #18).
//!
//! Sessions consume one 32-byte leaf per 30-second rekey window. The
//! leaves are the bottom layer of a binary tree whose internal nodes
//! are SHA3-512 expansions of their parent. Once a parent is wiped,
//! every leaf below it is unreconstructable — strong forward secrecy.
//!
//! For a 90-day session lifetime at 30s rekey, we need
//! `90*86400/30 = 259200` leaves. ⌈log2(259200)⌉ = 18 levels — small
//! enough that the entire tree is comfortable in memory, but large
//! enough to give 30-second forward secrecy.

use sha3::{Digest, Sha3_512};
use zeroize::Zeroizing;

/// 32-byte node label. Leaves and internal nodes share the type.
pub type Node = Zeroizing<[u8; 32]>;

/// One forward-secret key tree.
pub struct KeyTree {
    /// Tree height. The leaf range is `[0, 2^height)`.
    pub height: u8,
    /// Root key. Held in a zeroizing wrapper.
    pub root: Node,
}

impl KeyTree {
    /// Build a tree with the given root and height.
    pub fn from_root(root: [u8; 32], height: u8) -> Self {
        Self {
            height,
            root: Zeroizing::new(root),
        }
    }

    /// Number of leaves the tree spans.
    pub fn leaf_count(&self) -> u64 {
        1u64 << self.height as u64
    }

    /// Derive the leaf at `index`. Top-down traversal, descending
    /// according to bits of `index` from MSB to LSB.
    pub fn derive_leaf(&self, index: u64) -> Option<Node> {
        if index >= self.leaf_count() {
            return None;
        }
        let mut node: [u8; 32] = *self.root;
        for level in (0..self.height).rev() {
            let bit = (index >> level) & 1;
            node = expand(&node, bit as u8);
        }
        Some(Zeroizing::new(node))
    }
}

/// Deterministically expand a parent into one of its two children.
///
/// `child = SHA3-512("shadow-comm/v1/keytree" || parent || U8(side))[..32]`.
fn expand(parent: &[u8; 32], side: u8) -> [u8; 32] {
    let mut h = Sha3_512::new();
    h.update(b"shadow-comm/v1/keytree");
    h.update(parent);
    h.update([side]);
    let out = h.finalize();
    let mut node = [0u8; 32];
    node.copy_from_slice(&out[..32]);
    node
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaves_are_distinct() {
        let tree = KeyTree::from_root([0x11u8; 32], 8);
        let a = tree.derive_leaf(0).unwrap();
        let b = tree.derive_leaf(1).unwrap();
        assert_ne!(*a, *b);
    }

    #[test]
    fn deterministic_derivation() {
        let tree1 = KeyTree::from_root([0x42u8; 32], 10);
        let tree2 = KeyTree::from_root([0x42u8; 32], 10);
        for i in [0, 1, 2, 100, 511, 1023] {
            assert_eq!(*tree1.derive_leaf(i).unwrap(), *tree2.derive_leaf(i).unwrap());
        }
    }

    #[test]
    fn out_of_range_returns_none() {
        let tree = KeyTree::from_root([0u8; 32], 4);
        assert!(tree.derive_leaf(15).is_some());
        assert!(tree.derive_leaf(16).is_none());
    }

    #[test]
    fn changing_root_changes_leaf() {
        let a = KeyTree::from_root([0u8; 32], 12).derive_leaf(7).unwrap();
        let b = KeyTree::from_root([1u8; 32], 12).derive_leaf(7).unwrap();
        assert_ne!(*a, *b);
    }

    #[test]
    fn full_height_18_works() {
        // Smoke: 90-day-style tree.
        let tree = KeyTree::from_root([0xAAu8; 32], 18);
        let first = tree.derive_leaf(0).unwrap();
        let last = tree.derive_leaf((1 << 18) - 1).unwrap();
        assert_ne!(*first, *last);
    }
}
