pub use maglev_macros::HttpError;

// Requirements:
// - ? should "just work" in most cases
// - Easy to specify internal error message, external error message, and error code
// - Easy to create errors
// - Users create and grow their own error type
// - Standar JSON response, nice to have, way to customize
//
// We also need a clear way to return errors from this library, the maglev::Error type which easily maps to user's error types

// pub struct Error {
//     message: String,
//     code: StatusCode,
// }

// impl Error {
//     fn unauthorized(message: &str) -> Error {
//         Error { message: message.into(), code: StatusCode::UNAUTHORIZED }
//     }
// }

/// Google JSON Style Guide for Errors
///
/// <https://google.github.io/styleguide/jsoncstyleguide.xml?showone=error#error>
pub mod google {
    #[derive(serde::Serialize)]
    pub struct ErrorResponse {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub api_version: Option<&'static str>,
        pub error: ErrorBody,
    }

    #[derive(serde::Serialize)]
    pub struct ErrorBody {
        pub code: u16,
        pub message: String,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        pub errors: Vec<ErrorDetail>,
    }
    #[derive(serde::Serialize)]
    pub struct ErrorDetail {
        pub domain: String,
        pub reason: String,
        pub message: String,
    }

    impl ErrorResponse {
        pub fn new(code: u16, message: String) -> Self {
            ErrorResponse {
                api_version: None,
                error: ErrorBody {
                    code,
                    message,
                    errors: vec![],
                },
            }
        }
    }
}

/// JSend error response
///
/// <https://github.com/omniti-labs/jsend>
pub mod jsend {
    use serde_json::Value;

    #[derive(serde::Serialize)]
    pub struct ErrorResponse {
        status: &'static str,
        pub message: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub code: Option<u16>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub data: Option<Value>,
    }

    impl ErrorResponse {
        pub fn new(message: &str) -> Self {
            ErrorResponse {
                status: "error",
                message: message.into(),
                code: None,
                data: None,
            }
        }
    }
}
