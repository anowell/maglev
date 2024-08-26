dev:
    cargo watch -q -i bin -i website -x "check --all-features"

run *args:
    cargo run -p maglev-cli -- {{args}}
