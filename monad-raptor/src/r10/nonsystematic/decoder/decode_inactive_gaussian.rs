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

use crate::r10::nonsystematic::decoder::{BufferId, BufferState, Decoder};

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

    fn buffer_inactivated_xor_eq(&mut self, a: u16, b: u16) {
        let (aref, bref) =
            Self::get_two_mut(&mut self.buffer_state, usize::from(a), usize::from(b));

        debug_assert!(aref.state() == BufferState::Inactivated);

        debug_assert!(bref.state() == BufferState::Inactivated);

        for intermediate_symbol_id in &bref.intermediate_symbol_ids {
            let symbol = &mut self.intermediate_symbol_state[usize::from(*intermediate_symbol_id)];

            if !symbol.is_inactivated() {
                let ret = aref.intermediate_symbol_ids.remove(intermediate_symbol_id);
                debug_assert!(ret);
            } else if aref
                .intermediate_symbol_ids
                .insert_or_remove(*intermediate_symbol_id)
            {
                symbol.inactivated_insert(a);
            } else {
                symbol.inactivated_remove(a);
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

        let pivot_count = self.inactive_intermediate_symbol_ids_scratch.len();

        for step in 0..pivot_count {
            let Some((pivot_offset, _pivot_weight)) = self.inactive_buffer_indices_scratch[step..]
                .iter()
                .enumerate()
                .filter_map(|(offset, &buffer_index)| {
                    let weight = self.buffer_state[usize::from(buffer_index)]
                        .intermediate_symbol_ids
                        .len();

                    (weight != 0).then_some((offset, weight))
                })
                .min_by_key(|&(_offset, weight)| weight)
            else {
                break;
            };

            let pivot_index = step + pivot_offset;
            self.inactive_buffer_indices_scratch.swap(step, pivot_index);

            let reducing_buffer_index = self.inactive_buffer_indices_scratch[step];
            let pivot_intermediate_symbol_id = self.buffer_state
                [usize::from(reducing_buffer_index)]
            .first_intermediate_symbol_id();

            self.inactive_reducee_buffer_indices_scratch.clear();
            for &buffer_index in self.intermediate_symbol_state
                [usize::from(pivot_intermediate_symbol_id)]
            .inactivated_values()
            {
                if self.buffer_state[usize::from(buffer_index)].state() == BufferState::Inactivated
                {
                    self.inactive_reducee_buffer_indices_scratch
                        .push(buffer_index);
                }
            }

            for reducee_index in 0..self.inactive_reducee_buffer_indices_scratch.len() {
                let reducee_buffer_index =
                    self.inactive_reducee_buffer_indices_scratch[reducee_index];

                if reducee_buffer_index == reducing_buffer_index {
                    continue;
                }

                self.buffer_inactivated_xor_eq(reducee_buffer_index, reducing_buffer_index);

                xor_buffers(
                    self.buffer_index_to_buffer_id(reducee_buffer_index),
                    self.buffer_index_to_buffer_id(reducing_buffer_index),
                );
            }
        }

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
