use std::fmt::{self, Display};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug, Clone, Serialize, Deserialize)]
pub enum AuthErrorKind {
    #[error("Invalid response type: {0}")]
    InvalidResponseType(String),
    #[error("Missing auth query parameter: {0}")]
    MissingParam(String),
    #[error("Unexpected error: {0}")]
    Unexpected(String),
    #[error("Unauthorized client: {0}")]
    UnauthorizedClient(String),
    #[error("Unauthorized redirect URI: {0}")]
    UnauthorizedRedirectUri(String),
    #[error("Invalid URI: {0}")]
    InvalidUri(String),
    #[error("Invalid code challenge method: {0}, supported methods: S256")]
    InvalidCodeChallengeMethod(String),
    #[error("Invalid code challenge: {0}")]
    InvalidCodeChallenge(String),
    #[error("Invalid provider: {0}")]
    InvalidProvider(String),
}

impl AuthErrorKind {
    pub fn missing_param(param: impl Into<String>) -> Self {
        Self::MissingParam(param.into())
    }

    pub fn unexpected(msg: impl Display) -> Self {
        Self::Unexpected(msg.to_string())
    }
}

#[derive(Error, Debug, Clone, Serialize, Deserialize)]
pub struct AuthError {
    pub kind: AuthErrorKind,
    pub redirect_uri: String,
}

impl AuthError {
    pub fn new(kind: AuthErrorKind, redirect_uri: impl Into<String>) -> Self {
        Self {
            kind,
            redirect_uri: redirect_uri.into(),
        }
    }

    pub fn as_redirect(&self) -> String {
        format!("{}?error={}", self.redirect_uri, self.kind)
    }
}

impl Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind)
    }
}

impl From<AuthError> for AuthErrorKind {
    fn from(value: AuthError) -> Self {
        value.kind
    }
}
