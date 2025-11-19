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

pub trait MetricNames {
    const STATE_INITIATING_SESSIONS: &'static str;
    const STATE_RESPONDING_SESSIONS: &'static str;
    const STATE_TRANSPORT_SESSIONS: &'static str;
    const STATE_TOTAL_SESSIONS: &'static str;
    const STATE_ALLOCATED_INDICES: &'static str;
    const STATE_SESSIONS_BY_PUBLIC_KEY: &'static str;
    const STATE_SESSIONS_BY_SOCKET: &'static str;
    const STATE_INITIATED_SESSIONS_BY_SOCKET: &'static str;
    const STATE_SESSION_INDEX_ALLOCATED: &'static str;
    const STATE_SESSION_ESTABLISHED_INITIATOR: &'static str;
    const STATE_SESSION_ESTABLISHED_RESPONDER: &'static str;
    const STATE_SESSION_TERMINATED: &'static str;

    const FILTER_PASS: &'static str;
    const FILTER_SEND_COOKIE: &'static str;
    const FILTER_DROP: &'static str;

    const API_CONNECT: &'static str;
    const API_DECRYPT: &'static str;
    const API_ENCRYPT_BY_PUBLIC_KEY: &'static str;
    const API_ENCRYPT_BY_SOCKET: &'static str;
    const API_DISCONNECT: &'static str;
    const API_DISPATCH_CONTROL: &'static str;
    const API_NEXT_PACKET: &'static str;
    const API_TICK: &'static str;

    const DISPATCH_HANDSHAKE_INIT: &'static str;
    const DISPATCH_HANDSHAKE_RESPONSE: &'static str;
    const DISPATCH_COOKIE_REPLY: &'static str;
    const DISPATCH_KEEPALIVE: &'static str;

    const ERROR_CONNECT: &'static str;
    const ERROR_DECRYPT: &'static str;
    const ERROR_ENCRYPT_BY_PUBLIC_KEY: &'static str;
    const ERROR_ENCRYPT_BY_SOCKET: &'static str;
    const ERROR_DISPATCH_CONTROL: &'static str;

    const ERROR_SESSION_EXHAUSTED: &'static str;
    const ERROR_MAC1_VERIFICATION_FAILED: &'static str;
    const ERROR_TIMESTAMP_REPLAY: &'static str;
    const ERROR_SESSION_NOT_FOUND: &'static str;
    const ERROR_SESSION_INDEX_NOT_FOUND: &'static str;
    const ERROR_INVALID_RECEIVER_INDEX: &'static str;
    const ERROR_SESSION_NOT_ESTABLISHED_FOR_ADDRESS: &'static str;
    const ERROR_HANDSHAKE_INIT_VALIDATION: &'static str;
    const ERROR_HANDSHAKE_INIT_RESPONDER_NEW: &'static str;
    const ERROR_COOKIE_REPLY: &'static str;
    const ERROR_HANDSHAKE_RESPONSE_VALIDATION: &'static str;

    const ENQUEUED_HANDSHAKE_INIT: &'static str;
    const ENQUEUED_HANDSHAKE_RESPONSE: &'static str;
    const ENQUEUED_COOKIE_REPLY: &'static str;
    const ENQUEUED_KEEPALIVE: &'static str;

    const INITIATOR_BUFFERED_MESSAGES: &'static str;
    const INITIATOR_MESSAGES_SENT_FROM_BUFFER: &'static str;
    const INITIATOR_MESSAGES_DROPPED: &'static str;
}

#[macro_export]
macro_rules! define_metric_names {
    ($prefix:expr) => {
        const STATE_INITIATING_SESSIONS: &'static str =
            concat!("monad.wireauth", $prefix, "state.initiating_sessions");
        const STATE_RESPONDING_SESSIONS: &'static str =
            concat!("monad.wireauth", $prefix, "state.responding_sessions");
        const STATE_TRANSPORT_SESSIONS: &'static str =
            concat!("monad.wireauth", $prefix, "state.transport_sessions");
        const STATE_TOTAL_SESSIONS: &'static str =
            concat!("monad.wireauth", $prefix, "state.total_sessions");
        const STATE_ALLOCATED_INDICES: &'static str =
            concat!("monad.wireauth", $prefix, "state.allocated_indices");
        const STATE_SESSIONS_BY_PUBLIC_KEY: &'static str =
            concat!("monad.wireauth", $prefix, "state.sessions_by_public_key");
        const STATE_SESSIONS_BY_SOCKET: &'static str =
            concat!("monad.wireauth", $prefix, "state.sessions_by_socket");
        const STATE_INITIATED_SESSIONS_BY_SOCKET: &'static str = concat!(
            "monad.wireauth",
            $prefix,
            "state.initiated_sessions_by_socket"
        );
        const STATE_SESSION_INDEX_ALLOCATED: &'static str =
            concat!("monad.wireauth", $prefix, "state.session_index_allocated");
        const STATE_SESSION_ESTABLISHED_INITIATOR: &'static str = concat!(
            "monad.wireauth",
            $prefix,
            "state.session_established_initiator"
        );
        const STATE_SESSION_ESTABLISHED_RESPONDER: &'static str = concat!(
            "monad.wireauth",
            $prefix,
            "state.session_established_responder"
        );
        const STATE_SESSION_TERMINATED: &'static str =
            concat!("monad.wireauth", $prefix, "state.session_terminated");

        const FILTER_PASS: &'static str = concat!("monad.wireauth", $prefix, "filter.pass");
        const FILTER_SEND_COOKIE: &'static str =
            concat!("monad.wireauth", $prefix, "filter.send_cookie");
        const FILTER_DROP: &'static str = concat!("monad.wireauth", $prefix, "filter.drop");

        const API_CONNECT: &'static str = concat!("monad.wireauth", $prefix, "api.connect");
        const API_DECRYPT: &'static str = concat!("monad.wireauth", $prefix, "api.decrypt");
        const API_ENCRYPT_BY_PUBLIC_KEY: &'static str =
            concat!("monad.wireauth", $prefix, "api.encrypt_by_public_key");
        const API_ENCRYPT_BY_SOCKET: &'static str =
            concat!("monad.wireauth", $prefix, "api.encrypt_by_socket");
        const API_DISCONNECT: &'static str = concat!("monad.wireauth", $prefix, "api.disconnect");
        const API_DISPATCH_CONTROL: &'static str =
            concat!("monad.wireauth", $prefix, "api.dispatch_control");
        const API_NEXT_PACKET: &'static str = concat!("monad.wireauth", $prefix, "api.next_packet");
        const API_TICK: &'static str = concat!("monad.wireauth", $prefix, "api.tick");

        const DISPATCH_HANDSHAKE_INIT: &'static str =
            concat!("monad.wireauth", $prefix, "dispatch.handshake_initiation");
        const DISPATCH_HANDSHAKE_RESPONSE: &'static str =
            concat!("monad.wireauth", $prefix, "dispatch.handshake_response");
        const DISPATCH_COOKIE_REPLY: &'static str =
            concat!("monad.wireauth", $prefix, "dispatch.cookie_reply");
        const DISPATCH_KEEPALIVE: &'static str =
            concat!("monad.wireauth", $prefix, "dispatch.keepalive");

        const ERROR_CONNECT: &'static str = concat!("monad.wireauth", $prefix, "error.connect");
        const ERROR_DECRYPT: &'static str = concat!("monad.wireauth", $prefix, "error.decrypt");
        const ERROR_ENCRYPT_BY_PUBLIC_KEY: &'static str =
            concat!("monad.wireauth", $prefix, "error.encrypt_by_public_key");
        const ERROR_ENCRYPT_BY_SOCKET: &'static str =
            concat!("monad.wireauth", $prefix, "error.encrypt_by_socket");
        const ERROR_DISPATCH_CONTROL: &'static str =
            concat!("monad.wireauth", $prefix, "error.dispatch_control");

        const ERROR_SESSION_EXHAUSTED: &'static str =
            concat!("monad.wireauth", $prefix, "error.session_exhausted");
        const ERROR_MAC1_VERIFICATION_FAILED: &'static str =
            concat!("monad.wireauth", $prefix, "error.mac1_verification_failed");
        const ERROR_TIMESTAMP_REPLAY: &'static str =
            concat!("monad.wireauth", $prefix, "error.timestamp_replay");
        const ERROR_SESSION_NOT_FOUND: &'static str =
            concat!("monad.wireauth", $prefix, "error.session_not_found");
        const ERROR_SESSION_INDEX_NOT_FOUND: &'static str =
            concat!("monad.wireauth", $prefix, "error.session_index_not_found");
        const ERROR_INVALID_RECEIVER_INDEX: &'static str =
            concat!("monad.wireauth", $prefix, "error.invalid_receiver_index");
        const ERROR_SESSION_NOT_ESTABLISHED_FOR_ADDRESS: &'static str = concat!(
            "monad.wireauth",
            $prefix,
            "error.session_not_established_for_address"
        );
        const ERROR_HANDSHAKE_INIT_VALIDATION: &'static str =
            concat!("monad.wireauth", $prefix, "error.handshake_init_validation");
        const ERROR_HANDSHAKE_INIT_RESPONDER_NEW: &'static str = concat!(
            "monad.wireauth",
            $prefix,
            "error.handshake_init_responder_new"
        );
        const ERROR_COOKIE_REPLY: &'static str =
            concat!("monad.wireauth", $prefix, "error.cookie_reply");
        const ERROR_HANDSHAKE_RESPONSE_VALIDATION: &'static str = concat!(
            "monad.wireauth",
            $prefix,
            "error.handshake_response_validation"
        );

        const ENQUEUED_HANDSHAKE_INIT: &'static str =
            concat!("monad.wireauth", $prefix, "enqueued.handshake_init");
        const ENQUEUED_HANDSHAKE_RESPONSE: &'static str =
            concat!("monad.wireauth", $prefix, "enqueued.handshake_response");
        const ENQUEUED_COOKIE_REPLY: &'static str =
            concat!("monad.wireauth", $prefix, "enqueued.cookie_reply");
        const ENQUEUED_KEEPALIVE: &'static str =
            concat!("monad.wireauth", $prefix, "enqueued.keepalive");

        const INITIATOR_BUFFERED_MESSAGES: &'static str =
            concat!("monad.wireauth", $prefix, "initiator.buffered_messages");
        const INITIATOR_MESSAGES_SENT_FROM_BUFFER: &'static str = concat!(
            "monad.wireauth",
            $prefix,
            "initiator.messages_sent_from_buffer"
        );
        const INITIATOR_MESSAGES_DROPPED: &'static str =
            concat!("monad.wireauth", $prefix, "initiator.messages_dropped");
    };
}

#[macro_export]
macro_rules! impl_metric_names {
    ($type:ident, $transport:literal) => {
        impl $crate::metrics::MetricNames for $type {
            $crate::define_metric_names!(concat!(".", $transport, "."));
        }
    };
    ($type:ident) => {
        impl $crate::metrics::MetricNames for $type {
            $crate::define_metric_names!(".");
        }
    };
}

pub struct DefaultMetrics;

impl_metric_names!(DefaultMetrics);
