use crate::conn::retired;
use crate::conn::retired::storage;

pub(super) trait Remove<Tag> {
    fn remove(&mut self, start: u64) -> bool;
    fn remove_from(&mut self, index: storage::Index<Tag>, start: u64) -> bool;
    fn remove_internal(&mut self, parent: storage::Index<Tag>, at: usize);
    fn minimum(&self, index: storage::Index<Tag>) -> storage::Interval;
    fn maximum(&self, index: storage::Index<Tag>) -> storage::Interval;
    fn fill(&mut self, parent: storage::Index<Tag>, at: usize);
    fn borrow_previous(&mut self, parent: storage::Index<Tag>, at: usize);
    fn borrow_next(&mut self, parent: storage::Index<Tag>, at: usize);
    fn merge(&mut self, parent: storage::Index<Tag>, at: usize);
}

impl<Tag> Remove<Tag> for retired::Tree<Tag> {
    fn remove(&mut self, start: u64) -> bool {
        if self.root.is_none() || !self.remove_from(self.root, start) {
            return false;
        }
        self.len -= 1;
        if self.pool.get(self.root).len() == 0 && !self.pool.get(self.root).leaf {
            let old_root = self.root;
            self.root = self.pool.get(old_root).children[0];
            self.pool.release(old_root);
        }
        true
    }

    fn remove_from(&mut self, index: storage::Index<Tag>, start: u64) -> bool {
        let len = self.pool.get(index).len();
        let at = self.pool.get(index).keys[..len].partition_point(|range| range.start < start);
        if at != len && self.pool.get(index).keys[at].start == start {
            if self.pool.get(index).leaf {
                let node = self.pool.get_mut(index);
                node.keys.copy_within(at + 1..len, at);
                node.len -= 1;
            } else {
                self.remove_internal(index, at);
            }
            return true;
        }
        if self.pool.get(index).leaf {
            return false;
        }

        let last = at == len;
        let child = self.pool.get(index).children[at];
        if self.pool.get(child).len() < retired::MIN_DEGREE {
            self.fill(index, at);
        }
        let parent_len = self.pool.get(index).len();
        let child_at = if last && at > parent_len { at - 1 } else { at };
        let child = self.pool.get(index).children[child_at];
        self.remove_from(child, start)
    }

    fn remove_internal(&mut self, parent: storage::Index<Tag>, at: usize) {
        let key = self.pool.get(parent).keys[at];
        let left = self.pool.get(parent).children[at];
        let right = self.pool.get(parent).children[at + 1];
        if self.pool.get(left).len() >= retired::MIN_DEGREE {
            let predecessor = self.maximum(left);
            self.pool.get_mut(parent).keys[at] = predecessor;
            assert!(self.remove_from(left, predecessor.start));
        } else if self.pool.get(right).len() >= retired::MIN_DEGREE {
            let successor = self.minimum(right);
            self.pool.get_mut(parent).keys[at] = successor;
            assert!(self.remove_from(right, successor.start));
        } else {
            self.merge(parent, at);
            assert!(self.remove_from(left, key.start));
        }
    }

    fn minimum(&self, mut index: storage::Index<Tag>) -> storage::Interval {
        loop {
            let node = self.pool.get(index);
            if node.leaf {
                return node.keys[0];
            }
            index = node.children[0];
        }
    }

    fn maximum(&self, mut index: storage::Index<Tag>) -> storage::Interval {
        loop {
            let node = self.pool.get(index);
            if node.leaf {
                return node.keys[node.len() - 1];
            }
            index = node.children[node.len()];
        }
    }

    fn fill(&mut self, parent: storage::Index<Tag>, at: usize) {
        let parent_len = self.pool.get(parent).len();
        if at != 0 {
            let previous = self.pool.get(parent).children[at - 1];
            if self.pool.get(previous).len() >= retired::MIN_DEGREE {
                self.borrow_previous(parent, at);
                return;
            }
        }
        if at != parent_len {
            let next = self.pool.get(parent).children[at + 1];
            if self.pool.get(next).len() >= retired::MIN_DEGREE {
                self.borrow_next(parent, at);
                return;
            }
        }
        if at != parent_len {
            self.merge(parent, at);
        } else {
            self.merge(parent, at - 1);
        }
    }

    fn borrow_previous(&mut self, parent: storage::Index<Tag>, at: usize) {
        let child = self.pool.get(parent).children[at];
        let previous = self.pool.get(parent).children[at - 1];
        let child_len = self.pool.get(child).len();
        let previous_len = self.pool.get(previous).len();
        let separator = self.pool.get(parent).keys[at - 1];
        let replacement = self.pool.get(previous).keys[previous_len - 1];
        let descendant = self.pool.get(previous).children[previous_len];
        let child_leaf = self.pool.get(child).leaf;

        {
            let node = self.pool.get_mut(child);
            node.keys.copy_within(0..child_len, 1);
            if !child_leaf {
                node.children.copy_within(0..=child_len, 1);
                node.children[0] = descendant;
            }
            node.keys[0] = separator;
            node.len += 1;
        }
        self.pool.get_mut(parent).keys[at - 1] = replacement;
        self.pool.get_mut(previous).len -= 1;
    }

    fn borrow_next(&mut self, parent: storage::Index<Tag>, at: usize) {
        let child = self.pool.get(parent).children[at];
        let next = self.pool.get(parent).children[at + 1];
        let child_len = self.pool.get(child).len();
        let next_len = self.pool.get(next).len();
        let separator = self.pool.get(parent).keys[at];
        let replacement = self.pool.get(next).keys[0];
        let descendant = self.pool.get(next).children[0];
        let child_leaf = self.pool.get(child).leaf;
        let next_leaf = self.pool.get(next).leaf;

        {
            let node = self.pool.get_mut(child);
            node.keys[child_len] = separator;
            if !child_leaf {
                node.children[child_len + 1] = descendant;
            }
            node.len += 1;
        }
        self.pool.get_mut(parent).keys[at] = replacement;
        {
            let node = self.pool.get_mut(next);
            node.keys.copy_within(1..next_len, 0);
            if !next_leaf {
                node.children.copy_within(1..=next_len, 0);
            }
            node.len -= 1;
        }
    }

    fn merge(&mut self, parent: storage::Index<Tag>, at: usize) {
        let left = self.pool.get(parent).children[at];
        let right = self.pool.get(parent).children[at + 1];
        let left_len = self.pool.get(left).len();
        let right_len = self.pool.get(right).len();
        let separator = self.pool.get(parent).keys[at];
        let right_leaf = self.pool.get(right).leaf;

        self.pool.get_mut(left).keys[left_len] = separator;
        for offset in 0..right_len {
            let key = self.pool.get(right).keys[offset];
            self.pool.get_mut(left).keys[left_len + 1 + offset] = key;
        }
        if !right_leaf {
            for offset in 0..=right_len {
                let child = self.pool.get(right).children[offset];
                self.pool.get_mut(left).children[left_len + 1 + offset] = child;
            }
        }
        self.pool.get_mut(left).len = (left_len + right_len + 1) as u8;

        let parent_len = self.pool.get(parent).len();
        {
            let node = self.pool.get_mut(parent);
            node.keys.copy_within(at + 1..parent_len, at);
            node.children.copy_within(at + 2..=parent_len, at + 1);
            node.len -= 1;
        }
        self.pool.release(right);
    }
}
