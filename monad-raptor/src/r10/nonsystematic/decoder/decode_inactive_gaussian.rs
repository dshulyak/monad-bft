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

use std::num::NonZeroU16;

use crate::{
    ordered_set::OrderedSet,
    r10::nonsystematic::decoder::{BufferId, BufferState, Decoder, IntermediateSymbol},
};

#[derive(Debug)]
struct InactiveGaussianWorkspace {
    row_intermediate_symbol_ids: DenseSetCollection,
    intermediate_symbol_row_indices: DenseSetCollection,
}

#[derive(Debug)]
struct DenseSetCollection {
    words: Vec<u64>,
    lens: Vec<u16>,
    words_per_set: usize,
    universe_size: usize,
}

#[derive(Debug)]
struct DenseSetIter<'a> {
    words: &'a [u64],
    word_index: usize,
    current_word: u64,
}

impl DenseSetCollection {
    fn new(count: usize, universe_size: usize) -> Self {
        let words_per_set = universe_size.div_ceil(u64::BITS as usize);

        Self {
            words: vec![0; count * words_per_set],
            lens: vec![0; count],
            words_per_set,
            universe_size,
        }
    }

    fn count(&self) -> usize {
        self.lens.len()
    }

    fn words(&self, set_index: usize) -> &[u64] {
        let start = set_index * self.words_per_set;
        &self.words[start..start + self.words_per_set]
    }

    fn len(&self, set_index: u16) -> usize {
        usize::from(self.lens[usize::from(set_index)])
    }

    fn first(&self, set_index: u16) -> Option<u16> {
        for (word_index, &word) in self.words(usize::from(set_index)).iter().enumerate() {
            if word != 0 {
                let bit_index = word_index * u64::BITS as usize + word.trailing_zeros() as usize;
                debug_assert!(bit_index < self.universe_size);
                return Some(bit_index.try_into().unwrap());
            }
        }

        None
    }

    fn set_member(&mut self, set_index: u16, value: u16, present: bool) {
        let set_index = usize::from(set_index);
        let value = usize::from(value);
        debug_assert!(value < self.universe_size);
        let word_index = value / u64::BITS as usize;
        let bit_index = value % u64::BITS as usize;
        let mask = 1u64 << bit_index;
        let base = set_index * self.words_per_set;
        let words = &mut self.words[base..base + self.words_per_set];
        let was_present = (words[word_index] & mask) != 0;

        if was_present == present {
            return;
        }

        if present {
            words[word_index] |= mask;
            self.lens[set_index] += 1;
        } else {
            words[word_index] &= !mask;
            self.lens[set_index] -= 1;
        }
    }

    fn iter(&self, set_index: usize) -> DenseSetIter<'_> {
        DenseSetIter::new(self.words(set_index))
    }
}

impl<'a> DenseSetIter<'a> {
    fn new(words: &'a [u64]) -> Self {
        Self {
            words,
            word_index: 0,
            current_word: 0,
        }
    }
}

unsafe fn update_column_membership_bits_unchecked(
    words: *mut u64,
    lens: *mut u16,
    words_per_set: usize,
    row_word_index: usize,
    row_mask: u64,
    base_symbol_index: usize,
    mut bits: u64,
    present: bool,
) {
    while bits != 0 {
        let bit_index = bits.trailing_zeros() as usize;
        bits &= bits - 1;

        let symbol_index = base_symbol_index + bit_index;
        let word_offset = symbol_index * words_per_set + row_word_index;

        if present {
            unsafe {
                *words.add(word_offset) |= row_mask;
                *lens.add(symbol_index) += 1;
            }
        } else {
            unsafe {
                *words.add(word_offset) &= !row_mask;
                *lens.add(symbol_index) -= 1;
            }
        }
    }
}

impl Iterator for DenseSetIter<'_> {
    type Item = u16;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.current_word != 0 {
                let bit_index = self.current_word.trailing_zeros() as usize;
                self.current_word &= self.current_word - 1;
                let value = (self.word_index - 1) * u64::BITS as usize + bit_index;
                return Some(value.try_into().unwrap());
            }

            let next_word = *self.words.get(self.word_index)?;
            self.word_index += 1;
            self.current_word = next_word;
        }
    }
}

impl InactiveGaussianWorkspace {
    fn new(nrows: usize, ncols: usize) -> Self {
        Self {
            row_intermediate_symbol_ids: DenseSetCollection::new(nrows, ncols),
            intermediate_symbol_row_indices: DenseSetCollection::new(ncols, nrows),
        }
    }

    fn num_rows(&self) -> usize {
        self.row_intermediate_symbol_ids.count()
    }

    fn row_weight(&self, row_index: u16) -> usize {
        self.row_intermediate_symbol_ids.len(row_index)
    }

    fn row_first_intermediate_symbol_id(&self, row_index: u16) -> u16 {
        self.row_intermediate_symbol_ids.first(row_index).unwrap()
    }

    fn row_xor_eq(&mut self, a: u16, b: u16) {
        let a_index = usize::from(a);
        let b_index = usize::from(b);
        debug_assert_ne!(a_index, b_index);

        let row_words_per_set = self.row_intermediate_symbol_ids.words_per_set;
        let row_a_start = a_index * row_words_per_set;
        let row_b_start = b_index * row_words_per_set;

        let row_words = &mut self.row_intermediate_symbol_ids.words;
        let row_lens = &mut self.row_intermediate_symbol_ids.lens;
        let row_len = &mut row_lens[a_index];

        let (a_words, b_words): (&mut [u64], &[u64]) = if row_a_start < row_b_start {
            let (before_b, b_and_after) = row_words.split_at_mut(row_b_start);
            (
                &mut before_b[row_a_start..row_a_start + row_words_per_set],
                &b_and_after[..row_words_per_set],
            )
        } else {
            let (before_a, a_and_after) = row_words.split_at_mut(row_a_start);
            (
                &mut a_and_after[..row_words_per_set],
                &before_a[row_b_start..row_b_start + row_words_per_set],
            )
        };

        let column_words = &mut self.intermediate_symbol_row_indices.words;
        let column_lens = &mut self.intermediate_symbol_row_indices.lens;
        let column_words_per_set = self.intermediate_symbol_row_indices.words_per_set;
        let column_row_word_index = a_index / u64::BITS as usize;
        let column_row_mask = 1u64 << (a_index % u64::BITS as usize);
        let column_words_ptr = column_words.as_mut_ptr();
        let column_lens_ptr = column_lens.as_mut_ptr();
        let last_word_index = row_words_per_set - 1;
        let last_word_mask = match self.row_intermediate_symbol_ids.universe_size % u64::BITS as usize
        {
            0 => u64::MAX,
            rem => (1u64 << rem) - 1,
        };

        for (word_index, &raw_b_word) in b_words.iter().enumerate() {
            let b_word = if word_index == last_word_index {
                raw_b_word & last_word_mask
            } else {
                raw_b_word
            };
            if b_word == 0 {
                continue;
            }

            let before = a_words[word_index];
            let added = (!before) & b_word;
            let removed = before & b_word;

            a_words[word_index] = before ^ b_word;
            *row_len += added.count_ones() as u16;
            *row_len -= removed.count_ones() as u16;

            let base_symbol_index = word_index * u64::BITS as usize;
            // `b_word` is masked on the last partial word, so every bit maps to a valid symbol.
            unsafe {
                update_column_membership_bits_unchecked(
                    column_words_ptr,
                    column_lens_ptr,
                    column_words_per_set,
                    column_row_word_index,
                    column_row_mask,
                    base_symbol_index,
                    added,
                    true,
                );
                update_column_membership_bits_unchecked(
                    column_words_ptr,
                    column_lens_ptr,
                    column_words_per_set,
                    column_row_word_index,
                    column_row_mask,
                    base_symbol_index,
                    removed,
                    false,
                );
            }
        }
    }
}

impl Decoder {
    fn next_inactive_intermediate_symbol_generation(&mut self) -> u32 {
        self.inactive_intermediate_symbol_generation =
            self.inactive_intermediate_symbol_generation.wrapping_add(1);

        if self.inactive_intermediate_symbol_generation == 0 {
            self.inactive_intermediate_symbol_marks.fill(0);
            self.inactive_intermediate_symbol_generation = 1;
        }

        self.inactive_intermediate_symbol_generation
    }

    fn collect_inactivated_gaussian_inputs(&mut self) -> bool {
        self.inactive_buffer_indices_scratch.clear();
        self.buffers_inactivated.enumerate(|buffer_index, _weight| {
            self.inactive_buffer_indices_scratch.push(buffer_index)
        });

        let generation = self.next_inactive_intermediate_symbol_generation();
        let buffer_state = &self.buffer_state;
        let marks = &mut self.inactive_intermediate_symbol_marks;
        let columns = &mut self.inactive_intermediate_symbol_columns;
        let symbol_ids = &mut self.inactive_intermediate_symbol_ids_scratch;

        symbol_ids.clear();

        for &buffer_index in &self.inactive_buffer_indices_scratch {
            for &intermediate_symbol_id in
                &buffer_state[usize::from(buffer_index)].intermediate_symbol_ids
            {
                let mark_index = usize::from(intermediate_symbol_id);

                if marks[mark_index] != generation {
                    marks[mark_index] = generation;
                    columns[mark_index] = symbol_ids.len().try_into().unwrap();
                    symbol_ids.push(intermediate_symbol_id);
                }
            }
        }

        self.inactive_buffer_indices_scratch.len()
            >= self.inactive_intermediate_symbol_ids_scratch.len()
    }

    fn build_inactivated_gaussian_workspace(&self) -> InactiveGaussianWorkspace {
        let nrows = self.inactive_buffer_indices_scratch.len();
        let ncols = self.inactive_intermediate_symbol_ids_scratch.len();
        let mut workspace = InactiveGaussianWorkspace::new(nrows, ncols);

        for (local_row_index, &buffer_index) in
            self.inactive_buffer_indices_scratch.iter().enumerate()
        {
            let local_row_index: u16 = local_row_index.try_into().unwrap();

            for &intermediate_symbol_id in
                &self.buffer_state[usize::from(buffer_index)].intermediate_symbol_ids
            {
                let local_symbol_index =
                    self.inactive_intermediate_symbol_columns[usize::from(intermediate_symbol_id)];

                workspace
                    .row_intermediate_symbol_ids
                    .set_member(local_row_index, local_symbol_index, true);
                workspace
                    .intermediate_symbol_row_indices
                    .set_member(local_symbol_index, local_row_index, true);
            }
        }

        workspace
    }

    fn collect_preserved_inactivated_symbol_buffers(&self) -> Vec<OrderedSet> {
        let mut preserved = Vec::with_capacity(self.inactive_intermediate_symbol_ids_scratch.len());

        for &intermediate_symbol_id in &self.inactive_intermediate_symbol_ids_scratch {
            let IntermediateSymbol::Inactivated { buffer_indices } =
                &self.intermediate_symbol_state[usize::from(intermediate_symbol_id)]
            else {
                panic!();
            };

            let mut preserved_buffer_indices = OrderedSet::new();

            for &buffer_index in buffer_indices {
                if self.buffer_state[usize::from(buffer_index)].state() != BufferState::Inactivated
                {
                    preserved_buffer_indices.append(buffer_index);
                }
            }

            preserved.push(preserved_buffer_indices);
        }

        preserved
    }

    fn writeback_inactivated_gaussian_workspace(
        &mut self,
        workspace: &InactiveGaussianWorkspace,
        preserved_symbol_buffers: Vec<OrderedSet>,
    ) {
        for local_row_index in 0..workspace.num_rows() {
            let buffer_index = self.inactive_buffer_indices_scratch[local_row_index];
            let mut intermediate_symbol_ids =
                OrderedSet::with_universe_size(self.params.num_intermediate_symbols());

            for local_symbol_id in workspace.row_intermediate_symbol_ids.iter(local_row_index) {
                intermediate_symbol_ids.append_within_capacity(
                    self.inactive_intermediate_symbol_ids_scratch[usize::from(local_symbol_id)],
                );
            }

            self.buffer_state[usize::from(buffer_index)].intermediate_symbol_ids =
                intermediate_symbol_ids;
        }

        for (local_symbol_index, preserved_buffer_indices) in
            preserved_symbol_buffers.into_iter().enumerate()
        {
            let intermediate_symbol_id =
                self.inactive_intermediate_symbol_ids_scratch[local_symbol_index];

            let IntermediateSymbol::Inactivated { buffer_indices } =
                &mut self.intermediate_symbol_state[usize::from(intermediate_symbol_id)]
            else {
                panic!();
            };

            *buffer_indices = preserved_buffer_indices;
        }

        for local_symbol_index in 0..workspace.intermediate_symbol_row_indices.count() {
            let intermediate_symbol_id =
                self.inactive_intermediate_symbol_ids_scratch[local_symbol_index];
            let symbol = &mut self.intermediate_symbol_state[usize::from(intermediate_symbol_id)];

            for local_row_index in workspace.intermediate_symbol_row_indices.iter(local_symbol_index)
            {
                symbol.inactivated_insert(
                    self.inactive_buffer_indices_scratch[usize::from(local_row_index)],
                );
            }
        }
    }

    // Attempt Gaussian elimination on the inactivated intermediate symbols.
    pub fn try_inactive_gaussian(
        &mut self,
        xor_buffers: &mut impl FnMut(BufferId, BufferId),
    ) -> bool {
        // TODO: Don't perform Gaussian elimination while there are Active intermediate symbols?

        if self.buffers_inactivated.is_empty() {
            // Nothing to eliminate.
            return false;
        }

        if self.buffers_inactivated.peek_min().unwrap().1.get() == 1 {
            // There is an inactivated intermediate symbol we can reactivate, so there is no
            // need to perform Gaussian elimination at this point.
            return true;
        }

        if !self.collect_inactivated_gaussian_inputs() {
            // We need at least as many buffers as intermediate symbols for Gaussian
            // elimination to be successful.
            return false;
        }

        let workspace = self.build_inactivated_gaussian_workspace();
        let mut workspace = workspace;
        let mut row_order: Vec<u16> = (0..workspace.num_rows())
            .map(|row_index| row_index.try_into().unwrap())
            .collect();
        let pivot_count = self.inactive_intermediate_symbol_ids_scratch.len();

        for step in 0..pivot_count {
            let Some((pivot_offset, _pivot_weight)) = row_order[step..]
                .iter()
                .enumerate()
                .filter_map(|(offset, &row_index)| {
                    let weight = workspace.row_weight(row_index);

                    (weight != 0).then_some((offset, weight))
                })
                .min_by_key(|&(_offset, weight)| weight)
            else {
                break;
            };

            let pivot_index = step + pivot_offset;
            row_order.swap(step, pivot_index);

            let reducing_row_index = row_order[step];
            let reducing_buffer_index =
                self.inactive_buffer_indices_scratch[usize::from(reducing_row_index)];
            let pivot_intermediate_symbol_id =
                workspace.row_first_intermediate_symbol_id(reducing_row_index);

            self.inactive_reducee_buffer_indices_scratch.clear();
            for row_index in workspace
                .intermediate_symbol_row_indices
                .iter(usize::from(pivot_intermediate_symbol_id))
            {
                self.inactive_reducee_buffer_indices_scratch.push(row_index);
            }

            for &reducee_row_index in &self.inactive_reducee_buffer_indices_scratch {
                if reducee_row_index == reducing_row_index {
                    continue;
                }

                let reducee_buffer_index =
                    self.inactive_buffer_indices_scratch[usize::from(reducee_row_index)];

                workspace.row_xor_eq(reducee_row_index, reducing_row_index);

                xor_buffers(
                    self.buffer_index_to_buffer_id(reducee_buffer_index),
                    self.buffer_index_to_buffer_id(reducing_buffer_index),
                );
            }
        }

        let preserved_symbol_buffers = self.collect_preserved_inactivated_symbol_buffers();
        self.writeback_inactivated_gaussian_workspace(&workspace, preserved_symbol_buffers);

        for &buffer_index in &self.inactive_buffer_indices_scratch {
            let weight = self.buffer_state[usize::from(buffer_index)]
                .intermediate_symbol_ids
                .len();

            if weight > 0 {
                self.buffers_inactivated.update_buffer_weight(
                    usize::from(buffer_index),
                    NonZeroU16::new(weight.try_into().unwrap()).unwrap(),
                );
            } else {
                self.buffers_inactivated
                    .remove_buffer_weight(usize::from(buffer_index));

                self.num_redundant_buffers += 1;
            }
        }

        self.check();

        true
    }
}
