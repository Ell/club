use anyhow::{anyhow, Context, Result};
use serde::de::Error;
use serde::{Deserialize, Deserializer};
use std::str::FromStr;

#[derive(PartialEq, Debug)]
#[allow(dead_code)]
pub(crate) struct Snowflake {
    pub timestamp: u64,
    pub worker_id: u64,
    pub process_id: u64,
    pub increment: u64,
    pub flake: u64,
}

impl Snowflake {
    pub fn from(snowflake: u64) -> Snowflake {
        Snowflake {
            timestamp: (snowflake >> 22) + 1420070400000,
            worker_id: (snowflake & 0x3E0000) >> 17,
            process_id: (snowflake & 0x1F000) >> 12,
            increment: snowflake & 0xFFF,
            flake: snowflake,
        }
    }
}

impl<'de> Deserialize<'de> for Snowflake {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let snowflake_string: &str = Deserialize::deserialize(deserializer)?;
        let snowflake_uint = u64::from_str(snowflake_string).map_err(D::Error::custom)?;

        Ok(Snowflake::from(snowflake_uint))
    }
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
pub(crate) struct Role {
    pub id: Snowflake,
    pub name: String,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
pub(crate) struct Guild {
    pub id: Snowflake,
    pub name: String,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
pub(crate) struct GuildMember {
    pub user: Option<User>,
    pub nick: Option<String>,
    pub roles: Vec<Snowflake>,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
pub(crate) struct User {
    pub id: Snowflake,
    pub username: String,
    pub discriminator: String,
    pub global_name: Option<String>,
}

#[allow(dead_code)]
pub(crate) async fn get_discord_user_info(secret: &str) -> Result<User> {
    let client = reqwest::Client::new();

    client
        .get("https://discordapp.com/api/users/@me")
        .bearer_auth(secret)
        .send()
        .await
        .context("failed sending request to discord @me")?
        .json::<User>()
        .await
        .map_err(|e| anyhow!(e))
}

#[allow(dead_code)]
pub(crate) async fn get_discord_user_guild_list(secret: &str) -> Result<Vec<Guild>> {
    let client = reqwest::Client::new();

    client
        .get("https://discordapp.com/api/users/@me/guilds")
        .bearer_auth(secret)
        .send()
        .await
        .context("failed sending request to discord @me/guilds")?
        .json::<Vec<Guild>>()
        .await
        .map_err(|e| anyhow!(e))
}

#[allow(dead_code)]
pub(crate) async fn get_discord_user_guild_member_info(
    secret: &str,
    guild_id: u64,
) -> Result<GuildMember> {
    let request_url = format!(
        "https://discordapp.com/api/users/@me/guilds/{}/member",
        guild_id.to_string()
    );

    let client = reqwest::Client::new();
    client
        .get(request_url)
        .bearer_auth(secret)
        .send()
        .await
        .context("failed sending request to discord @me/guilds/{guild.id}/member")?
        .json::<GuildMember>()
        .await
        .map_err(|e| anyhow!(e))
}
