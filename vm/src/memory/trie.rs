//! A sparse trie of `CacheLine` structures which hold the memory of the
//! machine, backed by a Merkle tree for integrity checks.

use super::cacheline::*;
use super::path::*;
use super::Memory;
use crate::circuit::F;
use crate::error::*;
use tracing::{debug, error};

/// Represents a cryptographic digest.
type Digest = [u8; 32]; // Пример, зависит от кода проекта
/// Represents the parameters for hashing (e.g. Poseidon).
type Params = (); // Пример, заменить на реальный тип

/// A sparse Trie of `CacheLines` with merkle hashing.
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
    /// Internal nodes, with optionally populated children.
    Branch {
        left: Option<Box<Node>>,
        right: Option<Box<Node>>,
    },
    /// Leaf nodes, containing a single `CacheLine`.
    Leaf {
        val: CacheLine,
    },
}

use NodeData::*;

impl Node {
    /// Construct a new leaf node with default data.
    fn new_leaf() -> Self {
        Self {
            digest: Digest::default(),
            data: Leaf { val: CacheLine::default() },
        }
    }

    /// Construct a new internal node with unpopulated children.
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
            _ => {
                error!("Attempted to treat a Branch as a Leaf");
                &CacheLine::ZERO
            },
        }
    }

    #[inline]
    fn leaf_mut(&mut self) -> &mut CacheLine {
        match self {
            Leaf { val } => val,
            _ => {
                error!("Attempted to treat a Branch as a Leaf (mutable)");
                panic!("Invalid node type conversion");
            }
        }
    }

    #[inline]
    fn left(&self) -> &Option<Box<Node>> {
        match self {
            Branch { left, .. } => left,
            _ => {
                error!("Attempted to access left child of Leaf");
                &None
            }
        }
    }

    #[inline]
    fn right(&self) -> &Option<Box<Node>> {
        match self {
            Branch { right, .. } => right,
            _ => {
                error!("Attempted to access right child of Leaf");
                &None
            }
        }
    }
}

impl Node {
    /// Descend into a child node, allocating if necessary.
    /// If `leaf` is true, we create a Leaf node at the bottom level, otherwise a Branch node.
    fn descend(&mut self, is_left: bool, leaf: bool) -> &mut Box<Node> {
        let Node { data, .. } = self;
        let Branch { left, right } = match data {
            Branch { left, right } => (left, right),
            _ => {
                error!("Attempted to descend into a Leaf node");
                panic!("Invalid descent into leaf");
            }
        };

        let node = if is_left { left } else { right };
        if node.is_none() {
            let n = if leaf {
                Node::new_leaf()
            } else {
                Node::new_node()
            };
            *node = Some(Box::new(n));
        }

        node.as_mut().unwrap()
    }

    fn leaf(node: &Option<Box<Node>>) -> &CacheLine {
        match node {
            None => &CacheLine::ZERO,
            Some(n) => n.data.leaf(),
        }
    }

    fn child(node: &Option<Box<Node>>, is_left: bool) -> &Option<Box<Node>> {
        match node {
            None => &None,
            Some(n) => {
                if let Branch { left, right } = &n.data {
                    if is_left { left } else { right }
                } else {
                    &None
                }
            }
        }
    }

    fn sibling(node: &Node, is_left: bool) -> &Option<Box<Node>> {
        if let Branch { left, right } = &node.data {
            if is_left { right } else { left }
        } else {
            &None
        }
    }
}

impl MerkleTrie {
    /// Returns the Merkle root of the trie.
    #[allow(clippy::question_mark)]
    pub fn root(&self) -> Digest {
        self.digest(0, &self.root)
    }

    /// Return digest of node, or default if not present.
    fn digest(&self, level: usize, node: &Option<Box<Node>>) -> Digest {
        match node {
            None => self.zeros.get(level).cloned().unwrap_or_default(),
            Some(n) => n.digest,
        }
    }

    /// Query the tree at `addr`, returning the `CacheLine` and `Path`.
    /// Returns a default `CacheLine` if not populated.
    pub fn query(&self, addr: u32) -> (&CacheLine, Path) {
        debug!("Querying address {}", addr);
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

    /// Update the `CacheLine` at `addr` using the provided closure `f`.
    /// Returns a `Path` proving the new state.
    pub fn update<F>(&mut self, addr: u32, f: F) -> Result<Path>
    where
        F: Fn(&mut CacheLine) -> Result<()>,
    {
        debug!("Updating address {}", addr);
        let addr = addr.reverse_bits();
        let mut auth = Vec::new();
        if self.root.is_none() {
            self.root = Some(Box::new(Node::new_node()));
        }
        let root = self.root.as_mut().unwrap();
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

    /// Batch query multiple addresses at once.
    /// This can be useful if we want to reduce overhead by reusing some computation or simply
    /// make a single API call for multiple reads.
    pub fn batch_query(&self, addrs: &[u32]) -> Vec<(&CacheLine, Path)> {
        addrs.iter().map(|&addr| self.query(addr)).collect()
    }

    /// Batch update multiple addresses. Each update is applied in sequence.
    /// For higher performance, consider implementing a more sophisticated algorithm that
    /// re-uses traversal information.
    pub fn batch_update<F>(&mut self, updates: &[(u32, F)]) -> Result<Vec<Path>>
    where
        F: Fn(&mut CacheLine) -> Result<()>
    {
        let mut results = Vec::with_capacity(updates.len());
        for (addr, func) in updates {
            let r = self.update(*addr, func)?;
            results.push(r);
        }
        Ok(results)
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

// Тесты можно расширить, добавить больше сценариев, property-based тесты, fuzz-тесты
#[cfg(test)]
mod test {
    use super::super::path::test::*;
    use super::*;

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
    fn trie_update_single() {
        let mut mt = MerkleTrie::default();
        let _ = mt.update(0, |cl| cl.sw(0, 1)).unwrap();

        let cl = CacheLine::from([1u32, 0, 0, 0, 0, 0, 0, 0]);
        let x = mt.query(0);
        assert_eq!(cl, *x.0);
    }

    #[test]
    fn trie_batch_update() {
        let mut mt = MerkleTrie::default();
        let updates = vec![
            (0, |cl: &mut CacheLine| cl.sw(0, 1)),
            (1, |cl: &mut CacheLine| cl.sw(1, 2)),
        ];
        let res = mt.batch_update(&updates).unwrap();
        assert_eq!(res.len(), 2);

        let cl0 = CacheLine::from([1u32, 0, 0, 0, 0, 0, 0, 0]);
        let x0 = mt.query(0);
        assert_eq!(cl0, *x0.0);

        let cl1 = CacheLine::from([0, 2u32, 0, 0, 0, 0, 0, 0]);
        let x1 = mt.query(1);
        assert_eq!(cl1, *x1.0);
    }
}
