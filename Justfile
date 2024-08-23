dev:
    cargo watch -q -i bin -i website -x check

run *args:
    cargo run -p maglev-cli -- {{args}}
