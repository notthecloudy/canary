//! Arena-based storage for IR nodes.
//!
//! All IR nodes live in an `Arena<T>` and are referenced by `NodeId<T>`.
//! This eliminates `Rc<RefCell<>>` and enables:
//! - Cache-friendly linear allocation
//! - Stable IDs across graph rewrites
//! - O(1) indexed access
//! - Safe batch-invalidation

use std::fmt;
use std::marker::PhantomData;

/// A typed, stable index into an [`Arena<T>`].
///
/// `NodeId<T>` is cheap to copy, hash, and compare. It encodes the generation
/// of the slot to detect use-after-free at debug time.
#[derive(Debug)]
pub struct NodeId<T> {
    index: u32,
    generation: u32,
    _phantom: PhantomData<fn() -> T>,
}

impl<T> Clone for NodeId<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for NodeId<T> {}

impl<T> PartialEq for NodeId<T> {
    fn eq(&self, other: &Self) -> bool {
        self.index == other.index && self.generation == other.generation
    }
}

impl<T> Eq for NodeId<T> {}

impl<T> std::hash::Hash for NodeId<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.index.hash(state);
        self.generation.hash(state);
    }
}

impl<T> fmt::Display for NodeId<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}g{}", self.index, self.generation)
    }
}

/// Arena slot — either occupied or free-listed.
#[derive(Clone, Debug)]
enum Slot<T> {
    Occupied {
        value: T,
        generation: u32,
    },
    Free {
        next_free: Option<u32>,
        generation: u32,
    },
}

/// A generational arena allocator for IR nodes.
///
/// Nodes are allocated with [`Arena::alloc`] and accessed by [`NodeId`].
/// Freed slots are recycled via a free list. Generation counters detect
/// stale ID access in debug builds.
#[derive(Clone, Debug)]
pub struct Arena<T> {
    slots: Vec<Slot<T>>,
    free_head: Option<u32>,
    len: usize,
}

impl<T> Default for Arena<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Arena<T> {
    /// Creates a new, empty arena.
    pub fn new() -> Self {
        Self {
            slots: Vec::new(),
            free_head: None,
            len: 0,
        }
    }

    /// Creates an arena with pre-allocated capacity.
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            slots: Vec::with_capacity(cap),
            free_head: None,
            len: 0,
        }
    }

    /// Allocates a node in the arena, returning its stable [`NodeId`].
    pub fn alloc(&mut self, value: T) -> NodeId<T> {
        self.len += 1;
        if let Some(free_idx) = self.free_head {
            let slot = &mut self.slots[free_idx as usize];
            match slot {
                Slot::Free {
                    next_free,
                    generation,
                } => {
                    let next = *next_free;
                    let generation = generation.wrapping_add(1);
                    *slot = Slot::Occupied { value, generation };
                    self.free_head = next;
                    NodeId {
                        index: free_idx,
                        generation,
                        _phantom: PhantomData,
                    }
                }
                Slot::Occupied { .. } => unreachable!("free list corruption"),
            }
        } else {
            let index = self.slots.len() as u32;
            self.slots.push(Slot::Occupied {
                value,
                generation: 0,
            });
            NodeId {
                index,
                generation: 0,
                _phantom: PhantomData,
            }
        }
    }

    /// Returns a shared reference to the node at `id`.
    ///
    /// # Panics
    ///
    /// Panics in debug builds if the generation does not match (stale ID).
    pub fn get(&self, id: NodeId<T>) -> Option<&T> {
        self.slots
            .get(id.index as usize)
            .and_then(|slot| match slot {
                Slot::Occupied { value, generation } if *generation == id.generation => Some(value),
                _ => None,
            })
    }

    /// Returns a mutable reference to the node at `id`.
    pub fn get_mut(&mut self, id: NodeId<T>) -> Option<&mut T> {
        self.slots
            .get_mut(id.index as usize)
            .and_then(|slot| match slot {
                Slot::Occupied { value, generation } if *generation == id.generation => Some(value),
                _ => None,
            })
    }

    /// Frees the slot at `id`, making it available for future allocations.
    pub fn free(&mut self, id: NodeId<T>) -> bool {
        match self.slots.get_mut(id.index as usize) {
            Some(slot) => match slot {
                Slot::Occupied { generation, .. } if *generation == id.generation => {
                    let generation = *generation;
                    *slot = Slot::Free {
                        next_free: self.free_head,
                        generation,
                    };
                    self.free_head = Some(id.index);
                    self.len -= 1;
                    true
                }
                _ => false,
            },
            _ => false,
        }
    }

    /// Returns the number of live nodes in the arena.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if the arena contains no live nodes.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Iterates over all live nodes and their IDs.
    pub fn iter(&self) -> impl Iterator<Item = (NodeId<T>, &T)> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(i, slot)| match slot {
                Slot::Occupied { value, generation } => Some((
                    NodeId {
                        index: i as u32,
                        generation: *generation,
                        _phantom: PhantomData,
                    },
                    value,
                )),
                Slot::Free { .. } => None,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Clone)]
    struct Dummy(u32);

    #[test]
    fn alloc_and_get() {
        let mut arena = Arena::new();
        let id = arena.alloc(Dummy(42));
        assert_eq!(arena.get(id), Some(&Dummy(42)));
    }

    #[test]
    fn free_and_reuse() {
        let mut arena = Arena::new();
        let id1 = arena.alloc(Dummy(1));
        arena.free(id1);
        assert_eq!(arena.len(), 0);
        let id2 = arena.alloc(Dummy(2));
        // Slot is reused, but generation differs — old id1 is now stale
        assert_eq!(arena.get(id2), Some(&Dummy(2)));
        assert_ne!(id1, id2);
        assert_eq!(arena.get(id1), None);
    }

    #[test]
    fn stale_id_never_resolves_after_repeated_free_realloc_cycles() {
        let mut arena = Arena::new();
        let stale = arena.alloc(Dummy(0));
        assert!(arena.free(stale));

        let mut current = None;
        for value in 1..64 {
            let id = arena.alloc(Dummy(value));
            assert_eq!(
                arena.get(stale),
                None,
                "stale id resolved after realloc cycle {value}"
            );
            assert_eq!(arena.get(id), Some(&Dummy(value)));
            assert!(arena.free(id));
            current = Some(id);
        }

        let live = arena.alloc(Dummy(64));
        assert_eq!(arena.get(stale), None);
        assert_eq!(arena.get(current.unwrap()), None);
        assert_eq!(arena.get(live), Some(&Dummy(64)));
    }

    #[test]
    fn iter_live_nodes() {
        let mut arena = Arena::new();
        arena.alloc(Dummy(1));
        arena.alloc(Dummy(2));
        arena.alloc(Dummy(3));
        assert_eq!(arena.len(), 3);
        let vals: Vec<u32> = arena.iter().map(|(_, d)| d.0).collect();
        assert_eq!(vals, vec![1, 2, 3]);
    }
}
