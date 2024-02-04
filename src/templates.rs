use askama::Template;

#[derive(Template)]
#[template(path = "index.html")]
pub(crate) struct IndexTemplate {
    pub user: crate::database::User,
    pub game_servers: crate::games::GameServers,
}

#[derive(Template)]
#[template(path = "login.html")]
pub(crate) struct LoginTemplate {}

#[derive(Template)]
#[template(path = "profile.html")]
pub(crate) struct ProfileTemplate {
    pub user: crate::database::User,
    pub minecraft: String,
}
