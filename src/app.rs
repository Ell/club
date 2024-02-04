use anyhow::{Context, Result};
use askama::Template;
use async_session::{async_trait, CookieStore, Session, SessionStore};
use axum::extract::{FromRef, FromRequestParts, MatchedPath, Query, State};
use axum::http::header::{self, CONTENT_TYPE, SET_COOKIE};
use axum::http::request::Parts;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, RequestPartsExt, Router};
use axum_extra::typed_header::TypedHeaderRejectionReason;
use axum_extra::{headers, TypedHeader};
use oauth2::basic::BasicClient;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope,
    TokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};

use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;

use crate::discord;
use crate::games::GameServers;
use crate::templates::{IndexTemplate, LoginTemplate, ProfileTemplate};

const DISCORD_GUILD_ID: u64 = 1150114130125135954;
const DISCORD_ROLE_ID: u64 = 1150130649093652622;

const APP_CSS: &str = include_str!("../styles/site.css");

#[derive(Deserialize, Debug, Serialize, Clone)]
struct User {
    id: u64,
    username: String,
}

#[async_trait]
impl<S> FromRequestParts<S> for User
where
    CookieStore: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthRedirect;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let store = CookieStore::from_ref(state);

        let cookies = parts
            .extract::<TypedHeader<headers::Cookie>>()
            .await
            .map_err(|e| match *e.name() {
                header::COOKIE => match e.reason() {
                    TypedHeaderRejectionReason::Missing => AuthRedirect,
                    _ => {
                        tracing::error!("unexpected error getting cookies: {e}");
                        AuthRedirect
                    }
                },
                _ => panic!("unexpected error getting cookies: {e}"),
            })?;

        let session_cookie = cookies.get("_SESSION").ok_or(AuthRedirect)?;

        let session = store
            .load_session(session_cookie.to_string())
            .await
            .map_err(|_| AuthRedirect)?
            .ok_or(AuthRedirect)?;

        let user = session.get::<User>("user").ok_or(AuthRedirect)?;

        Ok(user)
    }
}

pub(crate) struct AppConfig {
    pub listen_address: String,
    pub discord_client_id: String,
    pub discord_client_secret: String,
    pub redirect_url: String,
    pub db_pool: Pool<Postgres>,
    pub game_servers: GameServers,
}

#[derive(Clone)]
struct AppState {
    oauth_client: BasicClient,
    db_pool: Pool<Postgres>,
    cookie_store: CookieStore,
    game_servers: GameServers,
}

impl FromRef<AppState> for BasicClient {
    fn from_ref(state: &AppState) -> Self {
        state.oauth_client.clone()
    }
}

impl FromRef<AppState> for Pool<Postgres> {
    fn from_ref(state: &AppState) -> Self {
        state.db_pool.clone()
    }
}

impl FromRef<AppState> for CookieStore {
    fn from_ref(state: &AppState) -> Self {
        state.cookie_store.clone()
    }
}

impl FromRef<AppState> for GameServers {
    fn from_ref(state: &AppState) -> Self {
        state.game_servers.clone()
    }
}

pub(crate) struct App {
    config: AppConfig,
}

impl App {
    pub(crate) fn new(config: AppConfig) -> Self {
        Self { config }
    }

    pub(crate) async fn run(&self) -> Result<(), AppError> {
        let oauth_client = create_oauth_client(
            &self.config.discord_client_id,
            &self.config.discord_client_secret,
            &self.config.redirect_url,
        )?;

        let db_pool = self.config.db_pool.clone();

        let cookie_store = CookieStore::new();

        let app_state = AppState {
            oauth_client,
            db_pool,
            cookie_store,
            game_servers: self.config.game_servers.clone(),
        };

        let router = Router::new()
            .route("/", get(index_handler))
            .route("/auth/discord", get(discord_auth_redirect_handler))
            .route("/auth/authorized", get(discord_auth_authorized_handler))
            .route("/profile", get(profile_handler))
            .route("/profile", post(profile_update_handler))
            .route("/logout", get(logout))
            .route("/site.css", get(css_handler))
            .layer(
                TraceLayer::new_for_http().make_span_with(|request: &Request<_>| {
                    let matched_path = request
                        .extensions()
                        .get::<MatchedPath>()
                        .map(MatchedPath::as_str);

                    tracing::info_span!(
                        "http_request",
                        method = ?request.method(),
                        matched_path,
                    )
                }),
            )
            .with_state(app_state);

        let listener = TcpListener::bind(&self.config.listen_address).await?;

        tracing::info!("Server listening on {}", listener.local_addr()?);

        axum::serve(listener, router).await?;

        Ok(())
    }
}

async fn css_handler() -> Result<impl IntoResponse, AppError> {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, "text/css".parse()?);

    Ok((headers, APP_CSS))
}

#[derive(Deserialize)]
struct ProfileUpdateForm {
    minecraft: Option<String>,
}

async fn profile_update_handler(
    State(db_pool): State<Pool<Postgres>>,
    user: User,
    Form(update_form): Form<ProfileUpdateForm>,
) -> Result<Redirect, AppError> {
    let profile = crate::database::Profile {
        minecraft: update_form.minecraft,
    };

    crate::database::update_user_profile(&db_pool, &user.id.to_string(), profile)
        .await
        .context("failed to update user profile")?;

    Ok(Redirect::to("/profile"))
}

async fn profile_handler(
    State(db_pool): State<Pool<Postgres>>,
    user: Option<User>,
) -> Result<impl IntoResponse, AppError> {
    let session = user.context("No user found")?;

    let user_id = session.id.to_string();
    let user = crate::database::get_user_by_id(&db_pool, &user_id)
        .await
        .context("failed to get user by id")?;

    let minecraft = match &user.profile {
        Some(profile) => profile.minecraft.clone().unwrap_or("".to_string()),
        None => "".to_string(),
    };

    let template = ProfileTemplate { user, minecraft };

    Ok(Html(template.render()?))
}

async fn index_handler(
    State(db_pool): State<Pool<Postgres>>,
    State(game_servers): State<GameServers>,
    user: Option<User>,
) -> Result<impl IntoResponse, AppError> {
    if let Some(session) = &user {
        let user_id = session.id.to_string();
        let user = crate::database::get_user_by_id(&db_pool, &user_id)
            .await
            .context("failed to get user by id")?;

        let template = IndexTemplate { user, game_servers };
        Ok(Html(template.render()?))
    } else {
        let template = LoginTemplate {};
        Ok(Html(template.render()?))
    }
}

async fn discord_auth_redirect_handler(
    State(oauth_client): State<BasicClient>,
) -> impl IntoResponse {
    let (auth_url, _csrf_token) = oauth_client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("identify".to_string()))
        .add_scope(Scope::new("guilds".to_string()))
        .add_scope(Scope::new("guilds.members.read".to_string()))
        .url();

    Redirect::to(auth_url.as_ref())
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct DiscordAuthRequest {
    code: Option<String>,
    state: String,
}

async fn discord_auth_authorized_handler(
    Query(query): Query<DiscordAuthRequest>,
    State(oauth_client): State<BasicClient>,
    State(db_pool): State<Pool<Postgres>>,
    State(store): State<CookieStore>,
) -> Result<impl IntoResponse, AppError> {
    let code = query.code.clone().unwrap_or_default();

    if code == "" {
        let cookie = format!("_SESSION=''; path=/;");
        let mut headers = HeaderMap::new();
        headers.insert(SET_COOKIE, cookie.parse()?);

        return Ok((headers, Redirect::to("/")));
    }

    let token = oauth_client
        .exchange_code(AuthorizationCode::new(code))
        .request_async(oauth2::reqwest::async_http_client)
        .await
        .context("failed sending request to authorization server")?;

    let token_secret = token.access_token().secret();

    let discord_user_data = discord::get_discord_user_info(&token_secret).await?;

    let is_painted = discord::get_discord_user_guild_member_info(&token_secret, DISCORD_GUILD_ID)
        .await
        .map(|data| {
            data.roles
                .iter()
                .map(|id| id.flake)
                .find(|id| *id == DISCORD_ROLE_ID)
                .is_some()
        })
        .unwrap_or_else(|_| false);

    if !is_painted {
        let cookie = format!("_SESSION=''; path=/;");
        let mut headers = HeaderMap::new();
        headers.insert(SET_COOKIE, cookie.parse()?);

        return Ok((headers, Redirect::to("/")));
    }

    let user = User {
        id: discord_user_data.id.flake,
        username: discord_user_data.username,
    };

    crate::database::insert_user(&db_pool, &user.id.to_string(), &user.username)
        .await
        .context("failed to insert user into database")?;

    let mut session = Session::new();
    session
        .insert("user", &user)
        .context("failed to insert user into session")?;

    let cookie = store.store_session(session).await?.unwrap_or_default();
    let cookie = format!("_SESSION={cookie}; SameSite=Lax; Path=/");

    let mut headers = HeaderMap::new();
    headers.insert(
        SET_COOKIE,
        cookie.parse().context("failed to parse cookie")?,
    );

    Ok((headers, Redirect::to("/")))
}

async fn logout() -> Result<impl IntoResponse, AppError> {
    let cookie = format!("_SESSION=''; path=/;");
    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, cookie.parse()?);

    Ok((headers, Redirect::to("/")))
}

fn create_oauth_client(
    client_id: &str,
    client_secret: &str,
    redirect_url: &str,
) -> Result<BasicClient, AppError> {
    let auth_url = "https://discord.com/api/oauth2/authorize?response_type=code".to_string();
    let token_url = "https://discord.com/api/oauth2/token".to_string();

    let client = BasicClient::new(
        ClientId::new(client_id.to_string()),
        Some(ClientSecret::new(client_secret.to_string())),
        AuthUrl::new(auth_url).context("failed to create new authorization server URL")?,
        Some(TokenUrl::new(token_url).context("failed to create new token endpoint URL")?),
    )
    .set_redirect_uri(
        RedirectUrl::new(redirect_url.to_string())
            .context("failed to create new redirection URL")?,
    );

    Ok(client)
}

#[derive(Debug)]
pub(crate) struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        tracing::error!("Application error: {:#}", self.0);

        (StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong").into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

struct AuthRedirect;

impl IntoResponse for AuthRedirect {
    fn into_response(self) -> Response {
        Redirect::temporary("/auth/discord").into_response()
    }
}
