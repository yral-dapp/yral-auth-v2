#[cfg(feature = "ssr")]
pub mod jwt_gen;

use std::{
    fmt::{self, Display},
    str::FromStr,
};

use base64::{prelude::BASE64_URL_SAFE, Engine};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::AuthErrorKind;

pub mod client;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Hash, Serialize, Deserialize)]
pub enum SupportedOAuthProviders {
    Google,
}

impl Display for SupportedOAuthProviders {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Google => write!(f, "google"),
        }
    }
}

impl FromStr for SupportedOAuthProviders {
    type Err = AuthErrorKind;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "google" => Ok(Self::Google),
            _ => Err(AuthErrorKind::InvalidProvider(s.to_string())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct AuthResponseCode;

impl FromStr for AuthResponseCode {
    type Err = AuthErrorKind;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "code" => Ok(Self),
            _ => Err(AuthErrorKind::InvalidResponseType(s.to_string())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CodeChallengeMethodS256;

impl FromStr for CodeChallengeMethodS256 {
    type Err = AuthErrorKind;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "S256" => Ok(Self),
            _ => Err(AuthErrorKind::InvalidCodeChallengeMethod(s.to_string())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CodeChallenge([u8; 32]);

impl FromStr for CodeChallenge {
    type Err = AuthErrorKind;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut res = [0u8; 32];
        let len = BASE64_URL_SAFE
            .decode_slice(s, &mut res)
            .map_err(|_| AuthErrorKind::InvalidCodeChallenge(s.to_string()))?;
        if len != 32 {
            return Err(AuthErrorKind::InvalidCodeChallenge(s.to_string()));
        }

        Ok(Self(res))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct AuthQuery {
    pub response_type: AuthResponseCode,
    pub client_id: String,
    pub redirect_uri: Url,
    pub state: String,
    pub code_challenge: CodeChallenge,
    pub code_challenge_method: CodeChallengeMethodS256,
    pub nonce: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthCodeClaims {
    aud: String,
    exp: usize,
    iat: usize,
    iss: String,
    sub: String,
    inner: AuthQuery,
}
