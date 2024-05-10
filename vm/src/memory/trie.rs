//! A Trie of `CacheLine` structures which hold the memory of the
//! machine. The trie can be configured as a Merkle tree dynamically.

use super::cacheline::*;
use super::path::*;
use super::Memory;
use crate::circuit::F;
use crate::error::*;

/// A sparse Trie of `CacheLines`.
#[derive(Default)]
pub struct MerkleTrie {
    // The root node, initially `None`
    root: Option<Box<Node>>,

    // Default hashes for each level of the tree
    zeros: Vec<Digest>,

    // The hash parameters.
    // If the hash parameters are None, then we will skip computing the hashes,
    // although other overheads remain to keep the code simple
    params: Option<Params>,
}

#[derive(Debug)]
struct Node {
    digest: Digest,
    data: NodeData,
}

#[derive(Debug)]
enum NodeData {
    Branch {
        left: Option<Box<Node>>,
        right: Option<Box<Node>>,
    },
    Leaf {
        val: CacheLine,
    },
}
use NodeData::*;

impl Node {
    fn new_leaf() -> Self {
        Self {
            digest: Digest::default(),
            data: Leaf { val: CacheLine::default() },
        }
    }

    fn new_node() -> Self {
        Self {
            digest: Digest::default(),
            data: Branch { left: None, right: None },
        }
    }
}

impl NodeData {
    fn leaf(&self) -> &CacheLine {
        match self {
            Leaf { val } => val,
            _ => panic!(),
        }
    }

    fn leaf_mut(&mut self) -> &mut CacheLine {
        match self {
            Leaf { val } => val,
            _ => panic!(),
        }
    }

    fn left(&self) -> &Option<Box<Node>> {
        match self {
            Branch { left, .. } => left,
            _ => panic!(),
        }
    }

    fn right(&self) -> &Option<Box<Node>> {
        match self {
            Branch { right, .. } => right,
            _ => panic!(),
        }
    }
}

impl Node {
    // descend into a child, allocating if necessary
    fn descend(&mut self, left: bool, leaf: bool) -> &mut Box<Node> {
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
            None => panic!(),
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
    pub fn new(hashes: bool) -> Self {
        let (params, zeros) = if hashes {
            let params = poseidon_config();
            let zeros = compute_zeros(&params).unwrap();
            (Some(params), zeros)
        } else {
            (None, Vec::new())
        };
        Self { root: None, zeros, params }
    }

    // return merkle root if present
    #[allow(clippy::question_mark)]
    pub fn root(&self) -> Option<Digest> {
        if self.params.is_none() {
            return None;
        }
        match &self.root {
            Some(n) => Some(n.digest),
            None => Some(self.zeros[0]),
        }
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
    pub fn query(&self, addr: u32) -> (&CacheLine, Option<Path>) {
        let addr = addr.reverse_bits();
        let mut auth = Vec::new();
        let cl = self.query_(&self.root, &mut auth, 0, addr);
        if self.params.is_some() {
            (
                cl,
                Some(Path::new(self.root().unwrap(), cl.scalars(), auth)),
            )
        } else {
            (cl, None)
        }
    }

    fn query_<'a>(
        &'a self,
        node: &'a Option<Box<Node>>,
        auth: &mut Vec<(bool, Digest)>,
        level: usize,
        addr: u32,
    ) -> &CacheLine {
        if level == CACHE_LOG {
            return Node::leaf(node);
        }

        let level = level + 1;
        let addr = addr >> 1;
        let is_left = (addr & 1) == 0;
        let cl = self.query_(Node::child(node, is_left), auth, level, addr);

        if self.params.is_some() {
            let sibling = Node::child(node, !is_left);
            auth.push((is_left, self.digest(level, sibling)));
        }
        cl
    }

    /// Update tree at `addr` with new `CacheLine`
    pub fn update<F>(&mut self, addr: u32, f: F) -> Result<Option<Path>>
    where
        F: Fn(&mut CacheLine) -> Result<()>,
    {
        let addr = addr.reverse_bits();
        let mut auth = Vec::new();
        if self.root.is_none() {
            self.root = Some(Box::new(Node::new_node()));
        }
        let Some(ref mut b) = self.root else { panic!() };
        let x = b as *mut Box<Node>;
        let y = unsafe { &mut *x as &mut Box<Node> };
        let cl = self.update_(y, &mut auth, 0, addr, f)?;
        if self.params.is_some() {
            Ok(Some(Path::new(self.root().unwrap(), cl, auth)))
        } else {
            Ok(None)
        }
    }

    fn update_<'a, UF>(
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
            if let Some(ref p) = &self.params {
                node.digest = hash_memory(p, node.data.leaf())?;
            }
            return Ok(node.data.leaf().scalars());
        }

        let level = level + 1;
        let addr = addr >> 1;
        let is_left = (addr & 1) == 0;
        let b = node.descend(is_left, level == CACHE_LOG);
        let cl = self.update_(b, auth, level, addr, f)?;

        if let Some(ref p) = &self.params {
            let sibling = Node::sibling(node, is_left);
            auth.push((is_left, self.digest(level, sibling)));
            let lh = self.digest(level, node.data.left());
            let rh = self.digest(level, node.data.right());
            node.digest = compress(p, &lh, &rh)?;
        }
        Ok(cl)
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
    use super::*;
    use super::super::path::test::*;

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
        let zeros = (&CacheLine::default(), None);
        let mt = MerkleTrie::new(false);
        assert_eq!(zeros, mt.query(0));

        let mt = MerkleTrie::new(true);
        let Some(params) = &mt.params else { panic!() };
        let x = mt.query(0);
        let path = x.1.unwrap();
        assert_eq!(zeros.0, x.0);
        assert!(path.verify(params).unwrap());
    }

    #[test]
    fn trie_empty_circuit() {
        let mt = MerkleTrie::new(true);
        let x = mt.query(0);
        let path = x.1.unwrap();

        verify_circuit_sat(&path);
    }

    #[test]
    fn trie_update() {
        let mut mt = MerkleTrie::new(false);
        let _ = mt.update(0, |cl| cl.sw(0, 1)).unwrap();

        let cl = CacheLine::from([1u32, 0, 0, 0, 0, 0, 0, 0]);
        let x = mt.query(0);
        assert_eq!(cl, *x.0);
    }

    #[test]
    fn trie_update_path() {
        let mut mt = MerkleTrie::new(true);
        let path = mt.update(0, |cl| cl.sw(0, 1)).unwrap().unwrap();

        let cl = CacheLine::from([1u32, 0, 0, 0, 0, 0, 0, 0]);
        let leaf = cl.scalars();
        assert_eq!(leaf, path.leaf);

        let x = mt.query(0);
        assert_eq!(cl, *x.0);

        let Some(params) = &mt.params else { panic!() };
        let Some(root) = mt.root() else { panic!() };
        assert_eq!(root, path.root);
        assert!(path.verify(params).unwrap());

        verify_circuit_sat(&path);
    }
}
