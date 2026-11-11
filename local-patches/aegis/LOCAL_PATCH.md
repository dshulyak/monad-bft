Local throughput experiment based on the unmodified crates.io aegis 0.9.20 package.

Only src/c/aegis128l.rs and src/pure_rust/aegis128l.rs add encrypt_into(). The
native backend delegates directly to the existing one-shot C routine using
separate input/output pointers. The pure-Rust backend uses its existing
incremental engine. No cipher construction or wire format changes are made.
Original upstream license and sources are retained. Remove the Cargo patch when
an appropriate upstream API is adopted.
