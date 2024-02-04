mod app;
mod database;
mod discord;
mod games;
mod templates;

use crate::app::{App, AppConfig};
use anyhow::Result;
use clap::Parser;
use sqlx::postgres::PgPoolOptions;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(clap::Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(long, env = "COOKIE_SECRET")]
    cookie_secret: String,
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,
    #[arg(long, env = "LISTEN_ADDRESS")]
    listen_address: String,
    #[arg(long, env = "REDIRECT_URL")]
    redirect_url: String,
    #[arg(long, env = "DISCORD_CLIENT_ID")]
    discord_client_id: String,
    #[arg(long, env = "DISCORD_CLIENT_SECRET")]
    discord_client_secret: String,
    #[arg(long, env = "MINECRAFT_SERVER_ADDRESS")]
    minecraft_server_address: String,
    #[arg(long, env = "MINECRAFT_RCON_PASSWORD")]
    minecraft_rcon_password: String,
    #[arg(long, env = "ENSHROUDED_SERVER_ADDRESS")]
    enshrouded_server_address: String,
    #[arg(long, env = "ENSHROUDED_SERVER_PASSWORD")]
    enshrouded_server_password: String,
    #[arg(long, env = "PALWORLD_SERVER_ADDRESS")]
    palworld_server_address: String,
    #[arg(long, env = "PALWORLD_SERVER_PASSWORD")]
    palworld_server_password: String,
    #[arg(long, env = "PALWORLD_RCON_PASSWORD")]
    palworld_rcon_password: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().unwrap();

    let args = Cli::parse();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "club=debug,tower_http=debug,axum::rejection=trace".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let db_pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&args.database_url)
        .await?;

    tracing::info!("Running migrations");
    sqlx::migrate!("./migrations").run(&db_pool).await.unwrap();
    tracing::info!("Migrations complete");

    let game_servers = games::GameServers {
        minecraft: games::MinecraftServer {
            address: args.minecraft_server_address,
            rcon_password: args.minecraft_rcon_password,
        },
        enshrouded: games::EnshroudedServer {
            address: args.enshrouded_server_address,
            password: args.enshrouded_server_password,
        },
        palworld: games::PalworldServer {
            address: args.palworld_server_address,
            password: args.palworld_server_password,
            rcon_password: args.palworld_rcon_password,
        },
    };

    let app_config = AppConfig {
        listen_address: args.listen_address,
        discord_client_id: args.discord_client_id,
        discord_client_secret: args.discord_client_secret,
        redirect_url: args.redirect_url,
        db_pool,
        game_servers,
    };

    let app = App::new(app_config);

    app.run().await.unwrap();

    Ok(())
}
