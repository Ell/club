use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct MinecraftServer {
    pub address: String,
    pub rcon_password: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct EnshroudedServer {
    pub address: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct PalworldServer {
    pub address: String,
    pub password: String,
    pub rcon_password: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct GameServers {
    pub minecraft: MinecraftServer,
    pub enshrouded: EnshroudedServer,
    pub palworld: PalworldServer,
}
