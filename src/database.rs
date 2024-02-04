use anyhow::Result;
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};

#[derive(Deserialize, Serialize, sqlx::FromRow)]
pub(crate) struct User {
    pub discord_id: String,
    pub username: String,
    pub profile: Option<sqlx::types::Json<Profile>>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct Profile {
    pub minecraft: Option<String>,
}

pub(crate) async fn get_user_by_id(db: &Pool<Postgres>, userid: &str) -> Result<User> {
    let query = "select * from users where discord_id = $1";

    sqlx::query_as::<_, User>(query)
        .bind(userid)
        .fetch_one(db)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get user by id: {}", e))
}

pub(crate) async fn insert_user(db: &Pool<Postgres>, userid: &str, username: &str) -> Result<()> {
    let query = "insert into users (discord_id, username) values ($1, $2) on conflict do nothing";

    sqlx::query(query)
        .bind(userid)
        .bind(username)
        .execute(db)
        .await
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!("Failed to insert user: {}", e))
}

pub(crate) async fn update_user_profile(
    db: &Pool<Postgres>,
    userid: &str,
    profile: Profile,
) -> Result<()> {
    let query = "update users set profile = $1 where discord_id = $2";

    sqlx::query(query)
        .bind(sqlx::types::Json(profile))
        .bind(userid)
        .execute(db)
        .await
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!("Failed to update user profile: {}", e))
}
