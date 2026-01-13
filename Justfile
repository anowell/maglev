dev:
    cargo watch -q -i bin -i website -x "check --all-features"

check:
    @echo "Checking Rust workspace..."
    cargo check --workspace --all-features
    @echo "Building all examples..."
    cargo build --all-targets --all-features -p maglev-examples
    @if [ -d "website" ]; then \
        echo "Checking website..."; \
        cd website && npm run check; \
    fi
    @echo "✓ All checks passed"

test *args:
    cargo test --lib --tests --all-features {{args}}

run *args:
    cargo run -p maglev-cli -- {{args}}

example name *args:
    cargo run --bin {{name}} --features {{name}} -p maglev-examples -- {{args}}
