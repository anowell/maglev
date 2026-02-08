//! Email message types and builder.

use serde::{Deserialize, Serialize};

use super::MailError;

/// The body content of an email.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EmailBody {
    /// Plain text only.
    Text(String),
    /// HTML only.
    Html(String),
    /// Both plain text and HTML (multipart/alternative).
    Multipart { text: String, html: String },
}

/// A complete email message ready to send.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Email {
    /// Primary recipients.
    pub to: Vec<String>,
    /// Carbon copy recipients.
    #[serde(default)]
    pub cc: Vec<String>,
    /// Blind carbon copy recipients.
    #[serde(default)]
    pub bcc: Vec<String>,
    /// Email subject line.
    pub subject: String,
    /// Email body content.
    pub body: EmailBody,
    /// Optional reply-to address.
    #[serde(default)]
    pub reply_to: Option<String>,
    /// Sender address.
    pub from: String,
}

impl Email {
    /// Create a new email builder.
    pub fn builder() -> EmailBuilder {
        EmailBuilder::default()
    }
}

/// Builder for constructing [`Email`] instances.
#[derive(Debug, Default)]
pub struct EmailBuilder {
    to: Vec<String>,
    cc: Vec<String>,
    bcc: Vec<String>,
    subject: Option<String>,
    text: Option<String>,
    html: Option<String>,
    reply_to: Option<String>,
    from: Option<String>,
}

impl EmailBuilder {
    /// Add a primary recipient.
    pub fn to(mut self, address: impl Into<String>) -> Self {
        self.to.push(address.into());
        self
    }

    /// Add multiple primary recipients.
    pub fn to_many(mut self, addresses: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.to.extend(addresses.into_iter().map(Into::into));
        self
    }

    /// Add a CC recipient.
    pub fn cc(mut self, address: impl Into<String>) -> Self {
        self.cc.push(address.into());
        self
    }

    /// Add a BCC recipient.
    pub fn bcc(mut self, address: impl Into<String>) -> Self {
        self.bcc.push(address.into());
        self
    }

    /// Set the subject line.
    pub fn subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    /// Set plain text body content.
    pub fn text(mut self, text: impl Into<String>) -> Self {
        self.text = Some(text.into());
        self
    }

    /// Set HTML body content.
    pub fn html(mut self, html: impl Into<String>) -> Self {
        self.html = Some(html.into());
        self
    }

    /// Set the reply-to address.
    pub fn reply_to(mut self, address: impl Into<String>) -> Self {
        self.reply_to = Some(address.into());
        self
    }

    /// Set the sender address (required).
    pub fn from(mut self, address: impl Into<String>) -> Self {
        self.from = Some(address.into());
        self
    }

    /// Build the email, validating required fields.
    pub fn build(self) -> Result<Email, MailError> {
        if self.to.is_empty() {
            return Err(MailError::Build("at least one recipient required".into()));
        }

        let from = self
            .from
            .ok_or_else(|| MailError::Build("from address required".into()))?;

        let subject = self
            .subject
            .ok_or_else(|| MailError::Build("subject required".into()))?;

        let body = match (self.text, self.html) {
            (Some(text), Some(html)) => EmailBody::Multipart { text, html },
            (Some(text), None) => EmailBody::Text(text),
            (None, Some(html)) => EmailBody::Html(html),
            (None, None) => return Err(MailError::Build("body required (text or html)".into())),
        };

        Ok(Email {
            to: self.to,
            cc: self.cc,
            bcc: self.bcc,
            subject,
            body,
            reply_to: self.reply_to,
            from,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_text_email() {
        let email = Email::builder()
            .from("sender@example.com")
            .to("user@example.com")
            .subject("Hello")
            .text("Body text")
            .build()
            .unwrap();

        assert_eq!(email.from, "sender@example.com");
        assert_eq!(email.to, vec!["user@example.com"]);
        assert_eq!(email.subject, "Hello");
        assert!(matches!(email.body, EmailBody::Text(t) if t == "Body text"));
    }

    #[test]
    fn build_multipart_email() {
        let email = Email::builder()
            .from("sender@example.com")
            .to("a@b.com")
            .subject("Test")
            .text("Plain")
            .html("<p>Rich</p>")
            .build()
            .unwrap();

        assert!(matches!(
            email.body,
            EmailBody::Multipart { text, html } if text == "Plain" && html == "<p>Rich</p>"
        ));
    }

    #[test]
    fn build_requires_from() {
        let result = Email::builder().to("a@b.com").subject("Hi").text("Body").build();
        assert!(result.is_err());
    }

    #[test]
    fn build_requires_recipient() {
        let result = Email::builder().from("a@b.com").subject("Hi").text("Body").build();
        assert!(result.is_err());
    }

    #[test]
    fn build_requires_subject() {
        let result = Email::builder().from("a@b.com").to("a@b.com").text("Body").build();
        assert!(result.is_err());
    }

    #[test]
    fn build_requires_body() {
        let result = Email::builder().from("a@b.com").to("a@b.com").subject("Hi").build();
        assert!(result.is_err());
    }
}
