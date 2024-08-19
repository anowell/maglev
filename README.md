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

- [x] Jwt Auth
- [x] HTTP error handling
- [x] Application config
- [x] Encryption/decryption utilities
- [x] Graceful shutdown
- [ ] SQLx data/model patterns
- [ ] OpenAPI spec generation
- [ ] Route helpers (e.g. CRUD) and listing (e.g. like `rails routes`)
- [ ] Admin functions (admin SQL, impersonation, etc.)
- [ ] Background workers (thread vs service, cron)
- [ ] Mailer patterns


## Maglev is NOT

For the forseeable future, Maglev is NOT:

- **Reinventing fundamentals**: We love Axum, SQLx, and many more core pieces of the ecosystem.
- **Prescribing frontend**: Pick the ideal frontend stack for your team - as long as it works with JSON APIs.
- **ORM-based**: Plenty of people love ORMs - awesome. We design and build with SQL front-and-center.
