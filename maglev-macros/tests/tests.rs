use http::StatusCode;
use maglev_macros::HttpError;
use std::borrow::Cow;

#[derive(thiserror::Error, Debug, HttpError)]
enum ApiError {
    #[error("authentication required")]
    #[http_error(UNAUTHORIZED)]
    Unauthorized,

    #[error("request path not found")]
    #[http_error(NOT_FOUND)]
    NotFound,

    #[error("bad request: {0}")]
    #[http_error(BAD_REQUEST)]
    BadRequest(Cow<'static, str>),

    #[error("Found ({0}, {1})")]
    #[http_error(IM_A_TEAPOT, "num={0} string={1}")]
    CodeAndMessage(u32, String),

    #[error("Found ({f1}, {f2})")]
    #[http_error(499, "f1={f1} f2={f2}")]
    Fields { f1: &'static str, f2: &'static str },

    #[error("db error: {0}")]
    #[http_error(INTERNAL_SERVER_ERROR, "an internal server error occurred")]
    Anyhow(#[from] anyhow::Error),
}

#[test]
fn test_http_error() {
    let unauthorized = ApiError::Unauthorized;
    assert_eq!(unauthorized.http_code(), StatusCode::UNAUTHORIZED);
    assert_eq!(unauthorized.http_message(), "authentication required");

    let not_found = ApiError::NotFound;
    assert_eq!(not_found.http_code(), StatusCode::NOT_FOUND);
    assert_eq!(not_found.http_message(), "request path not found");

    let bad_request = ApiError::BadRequest(Cow::Borrowed("Invalid request"));
    assert_eq!(bad_request.http_code(), StatusCode::BAD_REQUEST);
    assert_eq!(bad_request.http_message(), "bad request: Invalid request");

    let code_and_message = ApiError::CodeAndMessage(42, "Answer".into());
    assert_eq!(code_and_message.http_code(), StatusCode::IM_A_TEAPOT);
    assert_eq!(code_and_message.http_message(), "num=42 string=Answer");

    let fields = ApiError::Fields {
        f1: "fun",
        f2: "far",
    };
    assert_eq!(fields.http_code().as_u16(), 499);
    assert_eq!(fields.http_message(), "f1=fun f2=far");

    let anyhow_error = ApiError::Anyhow(anyhow::anyhow!("unexpected error"));
    assert_eq!(anyhow_error.http_code(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        anyhow_error.http_message(),
        "an internal server error occurred"
    );
}
