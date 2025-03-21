use std::sync::Arc;

use crate::error::{AuthError, AuthErrorKind};
use enum_dispatch::enum_dispatch;
use url::Url;

#[derive(Debug, Clone)]
struct OAuthClient {
    pub client_id: String,
    pub redirect_urls: Vec<Url>,
}

#[enum_dispatch]
pub(crate) trait ClientIdValidator {
    async fn validate_id_and_redirect(
        &self,
        client_id: &str,
        redirect_uri: &Url,
    ) -> Result<(), AuthError>;
}

impl<T: ClientIdValidator> ClientIdValidator for Arc<T> {
    async fn validate_id_and_redirect(
        &self,
        client_id: &str,
        redirect_uri: &Url,
    ) -> Result<(), AuthError> {
        self.as_ref()
            .validate_id_and_redirect(client_id, redirect_uri)
            .await
    }
}

pub struct ConstClientIdValidator {
    clients: Vec<OAuthClient>,
}

impl Default for ConstClientIdValidator {
    fn default() -> Self {
        Self {
            clients: vec![
                // Yral
                OAuthClient {
                    client_id: "31122c67-4801-4e70-82f0-08e12daa4f2d".to_string(),
                    redirect_urls: vec!["https://localhost:3000/".parse().unwrap()],
                },
            ],
        }
    }
}

impl ClientIdValidator for ConstClientIdValidator {
    async fn validate_id_and_redirect(
        &self,
        client_id: &str,
        redirect_uri: &Url,
    ) -> Result<(), AuthError> {
        let client = self.clients.iter().find(|c| c.client_id == client_id);
        let Some(client) = client else {
            return Err(AuthError::new(
                AuthErrorKind::UnauthorizedClient(client_id.to_string()),
                redirect_uri.to_string(),
            ));
        };
        if !client.redirect_urls.contains(redirect_uri) {
            return Err(AuthError::new(
                AuthErrorKind::UnauthorizedRedirectUri(redirect_uri.to_string()),
                redirect_uri.to_string(),
            ));
        }

        Ok(())
    }
}

#[derive(Clone)]
#[enum_dispatch(ClientIdValidator)]
pub enum ClientIdValidatorImpl {
    Const(Arc<ConstClientIdValidator>),
}
