# HeraclitusDB dev commands

default: test

build:
    cargo build --workspace

test:
    cargo test --workspace

# crash-injection suite at full CI strength
crash:
    CRASH_ITERS=1000 cargo test -p heraclitus-log --test crash_injection -- --nocapture

sim:
    cargo test -p heraclitus-sim

fuzz target="log_decode":
    cargo +nightly fuzz run {{target}} -- -max_total_time=600

bench:
    cargo bench --workspace

lint:
    cargo fmt --all --check
    cargo clippy --workspace --all-targets -- -D warnings
