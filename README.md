## Maglev

Batteries-included library for building JSON APIs.

Built on Axum and SQLx.

## Principles

**Maglev enables faster development of JSON APIs.**

- Just a library: does not replace Axum, merely extends it
- Pragmatic defaults: less time configuring to achieve good practices
- Focused: Maglev is all about JSON APIs built with Axum and SQLx

## Status

*Experimental: currently powering a pre-production system*

The current focus is extracting patterns from our existing system
and exploring experimental-level capabilities across these feature areas:

- [x] JWT Auth
- [x] HTTP error handling
- [x] Application config
- [x] Encryption/decryption utilities
- [x] Graceful shutdown
- [x] Background workers (in-memory queue, cron)
- [ ] SQLx data/model patterns
- [ ] Route helpers (e.g. CRUD) and listing (e.g. like `rails routes`)
- [ ] Admin functions (admin SQL, impersonation, etc.)
- [ ] Mailer patterns

## OpenAPI

For OpenAPI spec generation, use [utoipa-axum](https://github.com/juhaku/utoipa) directly - it integrates seamlessly with Axum and provides comprehensive schema generation.


## Maglev is NOT

For the forseeable future, Maglev is NOT:

- **Reinventing fundamentals**: We love Axum, SQLx, and many more core pieces of the ecosystem.
- **Prescribing frontend**: Pick the ideal frontend stack for your team - as long as it works with JSON APIs.
- **ORM-based**: Plenty of people love ORMs - awesome. We design and build with SQL front-and-center.

## Getting Started

To start a new app:

TBD


To add to an existing Axum app:

```
cargo add maglev --git https://github.com/meetsidebar/maglev.git

# or manually add to Cargo.toml:
maglev = { git = "https://github.com/meetsidebar/maglev.git" }
```



## Contributing

### Quick Setup

- Run `bin/bootstrap` (Arch✅, Ubuntu❔, and MacOS❔):

Should be ready to build and contribute.

### Manual bootstrap

`bin/bootstrap` attempts to install things The Right Way™️ for each platform.
But for the sake of developer control, here's the manual process:

  - Install [Rust](https://rustup.rs/)
  - Install cargo-watch: `cargo install cargo-watch`
  - Install [Just](https://github.com/casey/just) - `make` alternative. Run `just -l` to see available commands.


