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

use std::{iter, num::NonZeroU16};

use crate::{
    ordered_set::OrderedSet,
    r10::nonsystematic::decoder::{BufferId, BufferState, Decoder, IntermediateSymbol},
};

#[derive(Debug)]
struct InactiveGaussianWorkspace {
    row_intermediate_symbol_ids: Vec<OrderedSet>,
    intermediate_symbol_row_indices: Vec<OrderedSet>,
}

impl InactiveGaussianWorkspace {
    fn new(nrows: usize, ncols: usize) -> Self {
        Self {
            row_intermediate_symbol_ids: iter::repeat_with(|| {
                OrderedSet::with_universe_size(ncols)
            })
            .take(nrows)
            .collect(),
            intermediate_symbol_row_indices: iter::repeat_with(|| {
                OrderedSet::with_universe_size(nrows)
            })
            .take(ncols)
            .collect(),
        }
    }

    fn row_weight(&self, row_index: u16) -> usize {
        self.row_intermediate_symbol_ids[usize::from(row_index)].len()
    }

    fn row_first_intermediate_symbol_id(&self, row_index: u16) -> u16 {
        self.row_intermediate_symbol_ids[usize::from(row_index)]
            .first()
            .copied()
            .unwrap()
    }

    fn row_xor_eq(&mut self, a: u16, b: u16) {
        let (aref, bref) = Decoder::get_two_mut(
            &mut self.row_intermediate_symbol_ids,
            usize::from(a),
            usize::from(b),
        );

        for &intermediate_symbol_id in &*bref {
            if aref.insert_or_remove_within_capacity(intermediate_symbol_id) {
                self.intermediate_symbol_row_indices[usize::from(intermediate_symbol_id)]
                    .append_within_capacity(a);
            } else {
                let ret = self.intermediate_symbol_row_indices[usize::from(intermediate_symbol_id)]
                    .remove_within_capacity(a);
                debug_assert!(ret);
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

                workspace.row_intermediate_symbol_ids[usize::from(local_row_index)]
                    .append_within_capacity(local_symbol_index);
                workspace.intermediate_symbol_row_indices[usize::from(local_symbol_index)]
                    .append_within_capacity(local_row_index);
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
        workspace: InactiveGaussianWorkspace,
        preserved_symbol_buffers: Vec<OrderedSet>,
    ) {
        for (local_row_index, local_symbol_ids) in
            workspace.row_intermediate_symbol_ids.iter().enumerate()
        {
            let buffer_index = self.inactive_buffer_indices_scratch[local_row_index];
            let mut intermediate_symbol_ids = OrderedSet::new();

            for &local_symbol_id in local_symbol_ids {
                intermediate_symbol_ids.append(
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

        for (local_symbol_index, local_row_indices) in
            workspace.intermediate_symbol_row_indices.iter().enumerate()
        {
            let intermediate_symbol_id =
                self.inactive_intermediate_symbol_ids_scratch[local_symbol_index];
            let symbol = &mut self.intermediate_symbol_state[usize::from(intermediate_symbol_id)];

            for &local_row_index in local_row_indices {
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

        let mut workspace = self.build_inactivated_gaussian_workspace();
        let mut row_order: Vec<u16> = (0..workspace.row_intermediate_symbol_ids.len())
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
            for &row_index in &workspace.intermediate_symbol_row_indices
                [usize::from(pivot_intermediate_symbol_id)]
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
        self.writeback_inactivated_gaussian_workspace(workspace, preserved_symbol_buffers);

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
