use proc_macro::TokenStream;
use syn::{parse_macro_input, DeriveInput};

mod http_error;

/// Derive macro for mapping error variants to HTTP status and error message
///
/// Derive `HttpError` by adding `#[http_error(...)]` to each variant
///
/// `http_error` accepts one or two arguments
/// - status code (required)
/// - http error message (optional)
///
/// ### Status Code
///
/// May be specified as a `StatusCode` constant (e.g. `BAD_REQUEST`) or a number (e.g. `400`)
///
/// The `StatusCode` value is returned by calling `http_code()`;
///
/// ### HTTP Error Message
///
/// The https error message is a string literal which supports basic interpolation.
/// - Tuple variants can interpolate indices: `"first arg {0}, second arg {1}"`
/// - Struct variants can interpolate by field names: `message field = {message}`
///
/// By default (if not provided), `http_error` uses the `Display` implementation as a fallback.
/// This allows implementing `Error/Display` traits like normal (e.g. using `this_error`)
/// and providing an error message to `http_error` only when you want the user-facing error message
/// to be different than the internal log display of the error.
///
/// If your error type does NOT implement `Display`, then you'll need to provide the error message argument
/// for all variants.
///
/// The HTTP Error Message is returned by calling `http_message()`;
///
/// ### Example
///
/// ```rust,no_compile
/// #[derive(Debug, thiserror::Error, maglev::HttpError)]
/// enum Error {
///     // Basic usage with thiserror
///     #[error("authentication required")]
///     #[http_error(UNAUTHORIZED)]
///     Unauthorized,
///
///     // Supports error code by number
///     #[error("not found")]
///     #[http_error(404)]
///     NotFound,
///
///     // Custom error message to avoid exposing error details to users for security reasons
///     #[error("sqlx error: {0}")]
///     #[http_error(INTERNAL_SERVER_ERROR, "an error occurred with the database")]
///     Sqlx(#[from] sqlx::Error),
///
///     // Pragmatic usage of anyhow to capture context and backtraces on unrecoverable errors
///     #[error("Internal Server Error: {0:?}")]
///     #[http_error(INTERNAL_SERVER_ERROR, "an internal server error occurred")]
///     Anyhow(#[from] anyhow::Error),
///
///     // Overriding the HTTP error message for a tuple variant
///     #[error("bad request: {0}")]
///     #[http_error(BAD_REQUEST, "the request was not structured correctly: {0}")]
///     BadRequest(Cow<'static, str>),
///
///     // Overriding the HTTP error message for a struct variant
///     #[error("Error: {temp}°{unit}")]
///     #[http_error(IM_A_TEAPOT, "temp is {temp}°{unit}")]
///     Teapot{ temp: i32, unit: char },
/// }
///
///
/// // Example converting this Error into an `http::Response`
/// // Then this `Error` type can be returned from Axum handlers.
/// impl IntoResponse for Error {
///     fn into_response(self) -> Response {
///         // Trace server errors since we don't return the detailed error in the response body
///         if self.http_code().is_server_error() {
///             tracing::error!("Error Status {}: {}", self.http_code(), self);
///         }
///
///         // Construct a response
///         let body = Json(json!({
///             "error": {
///                 "code": self.http_code().as_u16(),
///                 "message": self.http_message()
///             }
///         }));
///         (self.http_code(), body).into_response()
///     }
/// }
/// ```
#[proc_macro_derive(HttpError, attributes(http_error))]
pub fn http_error_derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    http_error::http_error_derive_impl(input)
}
