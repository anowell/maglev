# Agent Instructions for Maglev

## Mission

Maglev is a batteries-included library for building JSON APIs with Rust. It extends (not replaces) Axum and SQLx with pragmatic defaults and focused patterns.

## Core Principles

1. **Just a library** - Extends Axum, doesn't replace it
2. **Pragmatic defaults** - Security and best practices out-of-box
3. **Focused** - JSON APIs with Axum and SQLx only
4. **SQL-first** - No ORM, embrace SQL with SQLx

## Key Design Decisions

### Why Not an ORM?
We prefer SQL-first development with SQLx for:
- Transparent query performance
- Direct control over database operations
- Compile-time checked queries
- No hidden N+1 queries or lazy loading surprises

### Why Extend Not Replace?
Maglev is designed as composable utilities:
- Users still write `Router::new()` and use Axum directly
- Maglev provides extractors, helpers, and patterns
- Easy incremental adoption - use what you need
- No vendor lock-in - pure Axum underneath

### Why Trait-Based APIs?
Traits enable customization without forking:
- `Job<S>` - Implement for custom background jobs
- `ValidateClaims<S>` - Custom JWT validation logic
- `QueueProvider<S>` - Pluggable job storage backends
- `ClaimsExtractor<S>` - Custom auth types

## Documentation Maintenance

### When to Update Docs

Update documentation when:
- Adding new features or modules
- Making breaking API changes
- Changing core design decisions
- Adding new patterns or best practices

### Documentation Structure

```
docs/
├── architecture.md    - High-level system design
├── auth.md           - Auth feature architecture
├── jobs.md           - Background jobs architecture
├── errors.md         - Error handling patterns
└── [feature].md      - Additional features as added
```

### Documentation Style

**Concise. Concise. Concise.**

- Focus on **why**, not **what** (code shows what)
- Document **design decisions** and **tradeoffs**
- Keep it **maintenance-focused** - help future contributors rebuild context
- **Not a tutorial** - users read code; docs explain architecture

#### Good Documentation Example
```markdown
## JWT Secret Key Size

Requires 32+ bytes. HMAC-SHA384 provides stronger collision resistance
than SHA256. Tradeoff: larger tokens (384 vs 256 bits), but negligible
for HTTP headers.
```

#### Bad Documentation Example
```markdown
## JWT Configuration

The JwtConfig struct allows you to configure JWT settings. You can set
the secret key, expiration time, and other options. The secret key must
be at least 32 bytes long. Here's how to use it:

[... lengthy tutorial code examples ...]
```

### Documentation Checklist

When adding a feature:
- [ ] Add concise doc in `docs/[feature].md`
- [ ] Document key design decisions
- [ ] Note tradeoffs and alternatives considered
- [ ] Update `docs/architecture.md` if system-level impact
- [ ] Keep it under 200 lines (break into sections if needed)

## Code Maintenance

### Testing Philosophy
- Prefer integration tests over unit tests
- Test public APIs, not internals
- Keep tests simple and focused
- Use real SQLx/Axum when possible (avoid heavy mocking)

### Adding Features
1. Ensure it aligns with core principles (JSON APIs, Axum/SQLx focused)
2. Provide trait-based extensibility where reasonable
3. Include pragmatic defaults
4. Write concise architecture doc
5. Update README roadmap if incomplete

### Dependency Updates

Update dependencies regularly:
```bash
cargo outdated --root-deps-only
cargo update
cargo test --all-features
```

**Breaking changes require:**
- Check for API changes in deps (especially axum, tower, tokio)
- Test examples compile (`cargo check --examples`)
- Document migration if needed

### Version Pinning

We use `=` for:
- Security-critical crates (orion, argon2)
- Major version 0.x crates that break often

We use `^` (default) for:
- Stable ecosystem crates (serde, tokio, axum)

## Current Priorities

Experimental status - focus on:
1. Extracting patterns from production use
2. Ergonomics and developer experience
3. Documentation and examples
4. Stability before 1.0

**Not priorities yet:**
- Performance optimization (good enough for now)
- Extensive customization options (YAGNI)
- Framework comparison benchmarks

## Agent Workflow

When asked to implement features:

1. **Read** existing code to understand patterns
2. **Design** with traits for extensibility
3. **Implement** with pragmatic defaults
4. **Document** architecture decisions (concise!)
5. **Test** with integration tests
6. **Update** README roadmap if needed

When asked to refactor:

1. **Understand** why current design exists (check docs)
2. **Consider** impact on existing users
3. **Maintain** backwards compatibility if possible
4. **Document** migration path if breaking
5. **Update** architecture docs with new decisions

## Questions to Ask

Before major changes, verify:
- Does this fit "JSON APIs with Axum/SQLx"?
- Can users still use Axum directly?
- Have we provided pragmatic defaults?
- Is this too framework-like? (we're a library!)
- Will this require extensive documentation? (keep it simple)

## References

- [Axum docs](https://docs.rs/axum)
- [SQLx docs](https://docs.rs/sqlx)
- [Tower docs](https://docs.rs/tower)
- [Tokio docs](https://docs.rs/tokio)
