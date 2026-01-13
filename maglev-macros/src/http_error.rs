extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::parse::Parser;
use syn::{DeriveInput, Expr, Lit, Meta};

pub(crate) fn http_error_derive_impl(input: DeriveInput) -> TokenStream {
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
                if attr.path().is_ident("http_error") {
                    if let Meta::List(meta_list) = &attr.meta {
                        let mut i = 0;
                        let parsed = syn::punctuated::Punctuated::<Expr, syn::Token![,]>::parse_terminated
                            .parse2(meta_list.tokens.clone());

                        if let Ok(args) = parsed {
                            for expr in args {
                                match expr {
                                    Expr::Path(path) if i == 0 => {
                                        let code = &path.path;
                                        http_code = Some(quote! { http::StatusCode::#code });
                                    }
                                    Expr::Lit(lit) if i == 0 => {
                                        if let Lit::Int(int_lit) = &lit.lit {
                                            let code = int_lit.base10_parse::<u16>().unwrap();
                                            http_code = Some(quote! { http::StatusCode::from_u16(#code).unwrap() });
                                        }
                                    }
                                    Expr::Lit(lit) if i == 1 => {
                                        if let Lit::Str(str_lit) = &lit.lit {
                                            http_message = Some(str_lit.value());
                                        }
                                    }
                                    _ => {}
                                }
                                i += 1;
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
