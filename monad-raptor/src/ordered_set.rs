// Copyright (C) 2025 Category Labs, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::slice;

#[derive(Clone, Debug)]
pub struct OrderedSet {
    values: Vec<u16>,
    positions: Vec<u16>,
}

impl OrderedSet {
    pub fn new() -> OrderedSet {
        OrderedSet {
            values: Vec::new(),
            positions: Vec::new(),
        }
    }

    pub fn with_universe_size(universe_size: usize) -> OrderedSet {
        OrderedSet {
            values: Vec::new(),
            positions: vec![0; universe_size],
        }
    }

    fn ensure_capacity(&mut self, value: u16) {
        let value = usize::from(value);
        if value >= self.positions.len() {
            self.positions.resize(value + 1, 0);
        }
    }

    fn position(&self, value: u16) -> Option<usize> {
        let value = usize::from(value);
        let raw = *self.positions.get(value)?;
        if raw == 0 {
            None
        } else {
            Some(usize::from(raw - 1))
        }
    }

    pub fn append(&mut self, value: u16) {
        self.ensure_capacity(value);
        debug_assert!(self.position(value).is_none());
        self.positions[usize::from(value)] = (self.values.len() + 1).try_into().unwrap();
        self.values.push(value);
    }

    pub fn append_within_capacity(&mut self, value: u16) {
        debug_assert!(usize::from(value) < self.positions.len());
        debug_assert!(self.position(value).is_none());
        self.positions[usize::from(value)] = (self.values.len() + 1).try_into().unwrap();
        self.values.push(value);
    }

    pub fn contains(&self, value: &u16) -> bool {
        self.position(*value).is_some()
    }

    pub fn first(&self) -> Option<&u16> {
        self.values.first()
    }

    pub fn insert(&mut self, value: u16) -> bool {
        if self.contains(&value) {
            false
        } else {
            self.append(value);
            true
        }
    }

    pub fn insert_or_remove(&mut self, value: u16) -> bool {
        if self.remove(&value) {
            false
        } else {
            self.append(value);
            true
        }
    }

    pub fn insert_or_remove_within_capacity(&mut self, value: u16) -> bool {
        debug_assert!(usize::from(value) < self.positions.len());
        if self.remove_within_capacity(value) {
            false
        } else {
            self.append_within_capacity(value);
            true
        }
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &u16> {
        self.values.iter()
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn remove(&mut self, value: &u16) -> bool {
        let Some(index) = self.position(*value) else {
            return false;
        };

        self.positions[usize::from(*value)] = 0;

        let removed = self.values.swap_remove(index);
        debug_assert_eq!(removed, *value);

        if let Some(moved) = self.values.get(index).copied() {
            self.positions[usize::from(moved)] = (index + 1).try_into().unwrap();
        }

        true
    }

    pub fn remove_within_capacity(&mut self, value: u16) -> bool {
        debug_assert!(usize::from(value) < self.positions.len());
        let index = usize::from(self.positions[usize::from(value)]);
        if index == 0 {
            return false;
        }

        let index = index - 1;
        self.positions[usize::from(value)] = 0;

        let removed = self.values.swap_remove(index);
        debug_assert_eq!(removed, value);

        if let Some(moved) = self.values.get(index).copied() {
            self.positions[usize::from(moved)] = (index + 1).try_into().unwrap();
        }

        true
    }
}

impl Default for OrderedSet {
    fn default() -> Self {
        Self::new()
    }
}

impl IntoIterator for OrderedSet {
    type Item = u16;
    type IntoIter = <Vec<u16> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.values.into_iter()
    }
}

impl<'a> IntoIterator for &'a OrderedSet {
    type Item = &'a u16;
    type IntoIter = slice::Iter<'a, u16>;

    fn into_iter(self) -> Self::IntoIter {
        self.values.iter()
    }
}
