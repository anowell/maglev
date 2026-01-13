# Error Handling Architecture

## What Maglev Provides

**`#[derive(HttpError)]` macro** that generates HTTP status codes and user-facing messages from error enums.

**Two standard error formats**: Google JSON Style and JSend (optional, use or ignore).

## The HttpError Macro

Annotate error variants with `#[http_error(STATUS_CODE, "optional message")]`:

```rust
#[derive(thiserror::Error, HttpError)]
enum AppError {
    #[error("not found")]
    #[http_error(NOT_FOUND)]
    NotFound,

    #[error("database error: {0}")]
    #[http_error(INTERNAL_SERVER_ERROR, "internal error")]
    Database(sqlx::Error),
}
```

**Generates two methods**:
- `http_code(&self) -> StatusCode`
- `http_message(&self) -> String`

## Key Design Decisions

### Separate Internal vs External Messages

`#[error("...")]` is internal (for logs, debugging).
`#[http_error(..., "...")]` is external (for users).

Never expose internal errors (SQL queries, stack traces) to API consumers. Security and UX both benefit.

### Two Methods, Not One

Separate `http_code()` and `http_message()` for flexibility - compose different response formats without coupling to a specific structure.

### Support for All Variant Types

**Unit variants**: `#[http_error(NOT_FOUND)]`
**Tuple variants**: Interpolate with `{0}`, `{1}` → `{}`
**Struct variants**: Interpolate with `{field_name}`

Macro handles field name preservation and transforms internally.

### Type-Safe Over Dynamic

Use typed errors (`thiserror`) not dynamic (`anyhow`) for library APIs. Compiler catches missing error cases, explicit HTTP mapping, clear boundaries.

`anyhow` is fine for examples, tests, CLI tools where flexibility matters more than type safety.

### Compose with thiserror

Use `#[from]` to wrap external errors:

```rust
#[derive(thiserror::Error, HttpError)]
enum AppError {
    #[error(transparent)]
    #[http_error(UNAUTHORIZED)]
    Auth(#[from] maglev::AuthError),
}
```

Enables `?` operator across error types while controlling HTTP responses.

## Typical Usage Pattern

```rust
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        if self.http_code().is_server_error() {
            tracing::error!("{}", self); // Log internal details
        }
        (self.http_code(), Json(json!({
            "message": self.http_message() // Return safe message
        }))).into_response()
    }
}
```

Log 5xx errors (server issues), don't log 4xx (client errors).

## Implementation Notes

**Macro parsing** (syn 2.0): Extracts status code (const or int) and optional message string from attributes.

**Code generation**: Match arms for each variant, handles interpolation by transforming `{0}` → `__self_0` internally.

**Zero runtime cost**: All code generation at compile time, match arms optimize to simple branches.

## Current Limitations

No structured error details (domain/reason fields), no localization, no custom error codes beyond HTTP status.

Future additions driven by real-world needs.
