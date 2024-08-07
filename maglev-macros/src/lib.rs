extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput, Meta, NestedMeta};

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
    let name = &input.ident;
    let mut unit_variants = Vec::new();
    let mut tuple_variants = Vec::new();
    let mut struct_variants = Vec::new();

    if let syn::Data::Enum(data_enum) = input.data {
        for variant in data_enum.variants {
            let ident = variant.ident;
            let attrs = variant.attrs;
            let mut http_code = None;
            let mut http_message = None;

            for attr in attrs {
                if attr.path.is_ident("http_error") {
                    if let Ok(Meta::List(meta_list)) = attr.parse_meta() {
                        for (i, nested) in meta_list.nested.iter().enumerate() {
                            match nested {
                                NestedMeta::Meta(syn::Meta::Path(path)) if i == 0 => {
                                    let code = path.clone();
                                    http_code = Some(quote! { http::StatusCode::#code });
                                    // http_code = Some(path.clone());
                                }
                                NestedMeta::Lit(syn::Lit::Int(lit)) if i == 0 => {
                                    let code = lit.base10_parse::<u16>().unwrap();
                                    http_code =
                                        Some(quote! { http::StatusCode::from_u16(#code).unwrap() });
                                    // http_code = Some(lit.base10_parse::<u16>().unwrap());
                                }
                                NestedMeta::Lit(syn::Lit::Str(lit)) if i == 1 => {
                                    http_message = Some(lit.value());
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }

            if let Some(http_code) = http_code {
                match variant.fields {
                    syn::Fields::Unit => {
                        unit_variants.push((ident, http_code, http_message));
                    }
                    syn::Fields::Unnamed(fields) => {
                        tuple_variants.push((ident, http_code, http_message, fields));
                    }
                    syn::Fields::Named(fields) => {
                        struct_variants.push((ident, http_code, http_message, fields));
                    }
                }
            }
        }
    }

    let unit_code_arms = unit_variants.iter().map(|(ident, http_code, _)| {
        quote! {
            Self::#ident => #http_code,
        }
    });

    let tuple_code_arms = tuple_variants.iter().map(|(ident, http_code, _, _)| {
        quote! {
            Self::#ident(..) => #http_code,
        }
    });

    let struct_code_arms = struct_variants.iter().map(|(ident, http_code, _, _)| {
        quote! {
            Self::#ident { .. } => #http_code,
        }
    });

    let unit_message_arms = unit_variants.iter().map(|(ident, _, http_message)| {
        let message_expr = if let Some(msg) = http_message {
            quote! { #msg.to_string() }
        } else {
            quote! { self.to_string() }
        };

        quote! {
            Self::#ident => #message_expr,
        }
    });

    let tuple_message_arms = tuple_variants
        .iter()
        .map(|(ident, _, http_message, fields)| {
            let field_names: Vec<syn::Ident> = (0..fields.unnamed.len())
                .map(|i| syn::Ident::new(&format!("__self_{}", i), proc_macro2::Span::call_site()))
                .collect();
            let field_patterns = field_names.iter().map(|name| quote! { #name });

            let message_expr = if let Some(msg) = http_message {
                let msg = prefix_numbers_in_braces(msg);
                quote! { format!(#msg) }
            } else {
                quote! { self.to_string() }
            };

            quote! {
                #[allow(unused_variables)]
                Self::#ident(#(#field_patterns),*) => #message_expr,
            }
        });

    let struct_message_arms = struct_variants
        .iter()
        .map(|(ident, _, http_message, fields)| {
            let field_names: Vec<&syn::Ident> = fields
                .named
                .iter()
                .map(|f| f.ident.as_ref().unwrap())
                .collect();

            let message_expr = if let Some(msg) = http_message {
                quote! { format!(#msg, #(#field_names = #field_names),*) }
            } else {
                quote! { self.to_string() }
            };

            quote! {
                #[allow(unused_variables)]
                Self::#ident { #(#field_names),* } => #message_expr,
            }
        });

    let expanded = quote! {
        impl #name {
            pub fn http_code(&self) -> http::StatusCode {
                match self {
                    #(#unit_code_arms)*
                    #(#tuple_code_arms)*
                    #(#struct_code_arms)*
                }
            }

            pub fn http_message(&self) -> String {
                match self {
                    #(#unit_message_arms)*
                    #(#tuple_message_arms)*
                    #(#struct_message_arms)*
                }
            }
        }
    };

    TokenStream::from(expanded)
}

fn prefix_numbers_in_braces(input: &str) -> String {
    let mut result = String::new();
    let mut inside_braces = false;

    for c in input.chars() {
        if c == '{' {
            inside_braces = true;
            result.push(c);
        } else if c == '}' {
            inside_braces = false;
            result.push(c);
        } else if inside_braces && c.is_ascii_digit() {
            result.push_str("__self_");
            result.push(c);
        } else {
            result.push(c);
        }
    }

    result
}
