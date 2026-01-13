# Maglev Examples

Example applications demonstrating Maglev features.

## Running Examples

```bash
# Run an example with defaults
just example basic

# Run directly with cargo
cargo run --bin basic --features basic -p maglev-examples
```

Examples use sensible defaults:
- **Port**: 3030
- **HMAC Key**: Demo key (not for production)

Override with environment variables:
```bash
PORT=8080 HMAC_KEY=your-key just example basic
```

## Available Examples

### basic
JWT authentication demo with user/admin roles.

**Endpoints**:
- `GET /health` - Health check
- `POST /login` - Login with credentials
- `POST /logout` - Logout (clear session)
- `GET /me` - Get current user (requires auth)
- `GET /admin` - Admin-only endpoint

**Demo credentials**:
- Username: `user`, Password: `password` (User role)
- Username: `admin`, Password: `admin` (Admin role)

**Example usage**:
```bash
# Start server
just example basic

# Login as user
curl -X POST http://localhost:3030/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"password"}' \
  -c cookies.txt

# Access protected endpoint
curl http://localhost:3030/me -b cookies.txt
```

## Adding New Examples

1. Create `src/{name}.rs`
2. Add to `Cargo.toml`:
```toml
[[bin]]
name = "{name}"
path = "src/{name}.rs"
required-features = ["{name}"]  # optional
```
3. Run with: `just example {name}`
