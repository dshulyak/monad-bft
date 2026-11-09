// Copyright (C) 2026 Category Labs, Inc.
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

use std::{
    future::Future,
    io::{Read, Write},
    os::unix::net::UnixStream,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll},
};

use futures::task::{waker_ref, ArcWake};

struct Signal {
    writer: UnixStream,
    pending: AtomicBool,
}

impl ArcWake for Signal {
    fn wake_by_ref(signal: &Arc<Self>) {
        if !signal.pending.swap(true, Ordering::AcqRel) {
            // Nonblocking and coalesced. A full socket already contains a wake;
            // a closed socket means the dataplane waiter has been dropped.
            loop {
                match (&signal.writer).write(&[1]) {
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    _ => break,
                }
            }
        }
    }
}

/// Turn cross-runtime channel notifications into io_uring readiness events.
/// Monoio's foreign-waker queue is drained when parking, but a busy UDP intake
/// can keep submitting completions without parking. Readiness completions are
/// also handled by that busy submission path, so batch permits and pin updates
/// cannot wait indefinitely behind continuously ready socket work.
pub(super) struct WakeBridge {
    signal: Arc<Signal>,
    socket: UnixStream,
    readiness: monoio::net::UnixStream,
}

impl WakeBridge {
    pub(super) fn new() -> Self {
        let (socket, writer) = UnixStream::pair().expect("UDP ingress wake socket");
        socket.set_nonblocking(true).unwrap();
        writer.set_nonblocking(true).unwrap();
        let readiness = monoio::net::UnixStream::from_std(socket.try_clone().unwrap()).unwrap();
        Self {
            signal: Arc::new(Signal {
                writer,
                pending: AtomicBool::new(false),
            }),
            socket,
            readiness,
        }
    }

    pub(super) async fn wait<F: Future>(&self, future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let waker = waker_ref(&self.signal);
        loop {
            if let Poll::Ready(value) = future.as_mut().poll(&mut Context::from_waker(&waker)) {
                return value;
            }
            // Readiness does not consume bytes, so cancelling this wait cannot
            // steal a later wait's notification through an orphaned read.
            self.readiness
                .readable(false)
                .await
                .expect("UDP ingress wake readiness");
            let mut socket = &self.socket;
            let mut buffer = [0; 64];
            loop {
                match socket.read(&mut buffer) {
                    Ok(0) => panic!("UDP ingress wake socket closed"),
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) => panic!("UDP ingress wake read: {error}"),
                }
            }
            self.signal.pending.store(false, Ordering::Release);
            // Recheck after clearing the coalescing flag to close the race with
            // a notification suppressed while the preceding byte was drained.
        }
    }
}
