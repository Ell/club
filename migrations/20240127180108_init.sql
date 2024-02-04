create table if not exists users (
    discord_id text not null unique,
    username text not null,
    profile jsonb default null
);
