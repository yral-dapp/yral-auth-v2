use crate::{components::spinner::Spinner, oauth::SupportedOAuthProviders};
use leptos::prelude::*;
use leptos_router::{components::Redirect, hooks::use_query, params::Params};

#[server]
pub async fn get_oauth_url(
    provider: SupportedOAuthProviders,
    client_state: String,
) -> Result<String, ServerFnError> {
    use super::server_impl::get_oauth_url_impl;
    get_oauth_url_impl(provider, client_state).await
}

#[derive(Debug, Clone, Params, PartialEq)]
pub struct OAuthRedirectorQueryMaybe {
    provider: Option<SupportedOAuthProviders>,
    state: Option<String>,
}

#[component]
pub fn OAuthRedirectorPage() -> impl IntoView {
    let query = use_query::<OAuthRedirectorQueryMaybe>();
    let oauth_url = Resource::new_blocking(
        move || query.get(),
        async move |query| {
            let query = query?;
            let Some(provider) = query.provider else {
                return Err(ServerFnError::new("invalid provider"));
            };
            let Some(state) = query.state else {
                return Err(ServerFnError::new("invalid state"));
            };

            get_oauth_url(provider, state).await
        },
    );

    view! {
        <Suspense fallback=|| view! { <div class="w-dvw h-dvh bg-black flex justify-center items-center"><Spinner /></div>}>
            {move || Suspend::new(async move {
                let url = oauth_url.await;
                match url {
                    Ok(url) => view! { <Redirect path=url /> },
                    Err(e) => view! { <Redirect path=format!("/error?error={e}") /> }
                }
            })}
        </Suspense>
    }
}
