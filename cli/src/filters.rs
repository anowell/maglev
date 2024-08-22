use askama::Result;
use heck::{
    ToKebabCase, ToLowerCamelCase, ToPascalCase, ToShoutySnakeCase, ToSnakeCase, ToTitleCase,
};

// Ensure the filters module is in scope wherever the template is used.
pub fn camel_case(s: impl AsRef<str>) -> Result<String> {
    Ok(s.as_ref().to_lower_camel_case())
}

pub fn pascal_case(s: impl AsRef<str>) -> Result<String> {
    Ok(s.as_ref().to_pascal_case())
}

pub fn snake_case(s: impl AsRef<str>) -> Result<String> {
    Ok(s.as_ref().to_snake_case())
}

pub fn kebab_case(s: impl AsRef<str>) -> Result<String> {
    Ok(s.as_ref().to_kebab_case())
}

pub fn shouty_snake_case(s: impl AsRef<str>) -> Result<String> {
    Ok(s.as_ref().to_shouty_snake_case())
}

pub fn title_case(s: impl AsRef<str>) -> Result<String> {
    Ok(s.as_ref().to_title_case())
}

pub fn pluralize(s: impl AsRef<str>) -> Result<String> {
    Ok(pluralizer::pluralize(s.as_ref(), 2, false))
}
