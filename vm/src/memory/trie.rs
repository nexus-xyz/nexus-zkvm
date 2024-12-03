//! A sparse trie of `CacheLine` structures which hold the memory of the
//! machine.

use super::cacheline::*;
use super::path::*;
use super::Memory;
use crate::circuit::F;
use crate::error::*;

/// A sparse Trie of `CacheLines` with merkle hashing..
pub struct MerkleTrie {
    // The root node, initially `None`
    root: Option<Box<Node>>,

    // Default hashes for each level of the tree
    zeros: Vec<Digest>,

    // The hash parameters.
    params: Params,
}

/// Populated nodes of the trie are represented by `Node`.
#[derive(Debug)]
struct Node {
    // The hash of the node data
    digest: Digest,

    // Contents of the node, either internal or leaf
    data: NodeData,
}

/// Populated nodes contain one `NodeData` value.
#[derive(Debug)]
enum NodeData {
    // internal nodes, with optionally populated children.
    Branch {
        left: Option<Box<Node>>,
        right: Option<Box<Node>>,
    },
    // leaf nodes, containing a single `CacheLine`.
    Leaf {
        val: CacheLine,
    },
}
use NodeData::*;

// Convenience methods for constructing internal and leaf nodes.
impl Node {
    // construct a new leaf node with default data.
    fn new_leaf() -> Self {
        Self {
            digest: Digest::default(),
            data: Leaf { val: CacheLine::default() },
        }
    }

    // construct a new internal node with unpopulated children.
    fn new_node() -> Self {
        Self {
            digest: Digest::default(),
            data: Branch { left: None, right: None },
        }
    }
}

impl NodeData {
    #[inline]
    fn leaf(&self) -> &CacheLine {
        match self {
            Leaf { val } => val,
            _ => unreachable!(),
        }
    }

    #[inline]
    fn leaf_mut(&mut self) -> &mut CacheLine {
        match self {
            Leaf { val } => val,
            _ => unreachable!(),
        }
    }

    #[inline]
    fn left(&self) -> &Option<Box<Node>> {
        match self {
            Branch { left, .. } => left,
            _ => unreachable!(),
        }
    }

    #[inline]
    fn right(&self) -> &Option<Box<Node>> {
        match self {
            Branch { right, .. } => right,
            _ => unreachable!(),
        }
    }
}

impl Node {
    // descend into a child, allocating if necessary
    fn descend(&mut self, left: bool, leaf: bool) -> &mut Box<Node> {
        // descending into a leaf node is an fatal error.
        let Node { data: Branch { left: l, right: r }, .. } = self else {
            panic!()
        };
        let node = if left { l } else { r };
        if node.is_none() {
            let n = if leaf {
                Node::new_leaf()
            } else {
                Node::new_node()
            };
            *node = Some(Box::new(n));
        }
        match node {
            Some(ref mut b) => b,
            None => unimplemented!(),
        }
    }

    // return leaf value, or default if not allocated
    fn leaf(node: &Option<Box<Node>>) -> &CacheLine {
        match node {
            None => &CacheLine::ZERO,
            Some(n) => n.data.leaf(),
        }
    }

    // return child of node, or `None` if not allocated
    fn child(node: &Option<Box<Node>>, left: bool) -> &Option<Box<Node>> {
        match node {
            None => &None,
            Some(n) if left => n.data.left(),
            Some(n) => n.data.right(),
        }
    }

    // same as `child`, but with a allocated node, and reversing the
    // use of the `left` parameter
    fn sibling(node: &Node, left: bool) -> &Option<Box<Node>> {
        if left {
            node.data.right()
        } else {
            node.data.left()
        }
    }
}

impl MerkleTrie {
    // return merkle root
    #[allow(clippy::question_mark)]
    pub fn root(&self) -> Digest {
        self.digest(0, &self.root)
    }

    // return digest of node, or default if not present
    fn digest(&self, level: usize, node: &Option<Box<Node>>) -> Digest {
        match node {
            None => self.zeros[level],
            Some(n) => n.digest,
        }
    }

    /// Query the tree at `addr` returning the `CacheLine` (and `Path` if hashes enabled).
    /// The default CacheLine is returned if the tree is unpopulated at `addr`.
    pub fn query(&self, addr: u32) -> (&CacheLine, Path) {
        let addr = addr.reverse_bits();
        let mut auth = Vec::new();
        let cl = self.query_inner(&self.root, &mut auth, 0, addr);
        let path = Path::new(self.root(), cl.scalars(), auth);
        (cl, path)
    }

    fn query_inner<'a>(
        &'a self,
        node: &'a Option<Box<Node>>,
        auth: &mut Vec<(bool, Digest)>,
        level: usize,
        addr: u32,
    ) -> &'a CacheLine {
        if level == CACHE_LOG {
            return Node::leaf(node);
        }

        let level = level + 1;
        let addr = addr >> 1;
        let is_left = (addr & 1) == 0;
        let cl = self.query_inner(Node::child(node, is_left), auth, level, addr);

        let sibling = Node::child(node, !is_left);
        auth.push((is_left, self.digest(level, sibling)));
        cl
    }

    /// Update `CacheLine` at `addr`.
    pub fn update<F>(&mut self, addr: u32, f: F) -> Result<Path>
    where
        F: Fn(&mut CacheLine) -> Result<()>,
    {
        let addr = addr.reverse_bits();
        let mut auth = Vec::new();
        if self.root.is_none() {
            self.root = Some(Box::new(Node::new_node()));
        }
        let Some(ref mut b) = self.root else { unreachable!() };

        // Note: root is never accessed through self in update_inner,
        // so we can safely make the following optimization
        let root = b as *mut Box<Node>;
        let root = unsafe { &mut *root as &mut Box<Node> };
        let cl = self.update_inner(root, &mut auth, 0, addr, f)?;
        Ok(Path::new(self.root(), cl, auth))
    }

    fn update_inner<'a, UF>(
        &'a self,
        node: &'a mut Box<Node>,
        auth: &mut Vec<(bool, Digest)>,
        level: usize,
        addr: u32,
        f: UF,
    ) -> Result<[F; 2]>
    where
        UF: Fn(&mut CacheLine) -> Result<()>,
    {
        if level == CACHE_LOG {
            f(node.data.leaf_mut())?;
            node.digest = hash_memory(&self.params, node.data.leaf())?;
            return Ok(node.data.leaf().scalars());
        }

        let level = level + 1;
        let addr = addr >> 1;
        let is_left = (addr & 1) == 0;
        let b = node.descend(is_left, level == CACHE_LOG);
        let cl = self.update_inner(b, auth, level, addr, f)?;

        let sibling = Node::sibling(node, is_left);
        auth.push((is_left, self.digest(level, sibling)));
        let lh = self.digest(level, node.data.left());
        let rh = self.digest(level, node.data.right());
        node.digest = compress(&self.params, &lh, &rh)?;
        Ok(cl)
    }
}

impl Default for MerkleTrie {
    fn default() -> Self {
        let params = poseidon_config();
        let zeros = compute_zeros(&params).unwrap();
        Self { root: None, zeros, params }
    }
}

impl Memory for MerkleTrie {
    type Proof = Path;

    fn query(&self, addr: u32) -> (&CacheLine, Self::Proof) {
        self.query(addr)
    }

    fn update<F>(&mut self, addr: u32, f: F) -> Result<Self::Proof>
    where
        F: Fn(&mut CacheLine) -> Result<()>,
    {
        self.update(addr, f)
    }
}

#[cfg(test)]
mod test {
    use super::super::path::test::*;
    use super::*;

    #[test]
    #[should_panic]
    fn node_missing() {
        let data = Leaf { val: CacheLine::default() };
        let _ = data.left();
    }

    #[test]
    fn node_alloc() {
        let mut node = Node::new_node();
        match node.data {
            Branch { left: None, right: None } => (),
            _ => panic!(),
        }

        let _left = node.descend(true, true);
        assert!(node.data.left().is_some());
        assert!(node.data.right().is_none());

        let _right = node.descend(false, true);
        assert!(node.data.left().is_some());
        assert!(node.data.right().is_some());
    }

    #[test]
    fn trie_query_empty() {
        let zeros = &CacheLine::default();
        let mt = MerkleTrie::default();
        let params = &mt.params;
        let x = mt.query(0);
        let path = x.1;
        assert_eq!(zeros, x.0);
        assert!(path.verify(params).unwrap());
    }

    #[test]
    fn trie_empty_circuit() {
        let mt = MerkleTrie::default();
        let x = mt.query(0);
        let path = x.1;

        verify_circuit_sat(&path);
    }

    #[test]
    fn trie_update() {
        let mut mt = MerkleTrie::default();
        let _ = mt.update(0, |cl| cl.sw(0, 1)).unwrap();

        let cl = CacheLine::from([1u32, 0, 0, 0, 0, 0, 0, 0]);
        let x = mt.query(0);
        assert_eq!(cl, *x.0);
    }

    #[test]
    fn trie_update_path() {
        let mut mt = MerkleTrie::default();
        let path = mt.update(0, |cl| cl.sw(0, 1)).unwrap();

        let cl = CacheLine::from([1u32, 0, 0, 0, 0, 0, 0, 0]);
        let leaf = cl.scalars();
        assert_eq!(leaf, path.leaf);

        let x = mt.query(0);
        assert_eq!(cl, *x.0);

        let params = &mt.params;
        let root = mt.root();
        assert_eq!(root, path.root);
        assert!(path.verify(params).unwrap());

        verify_circuit_sat(&path);
    }
}
