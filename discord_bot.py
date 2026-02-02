import asyncio
import os
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

import aiomysql
import bcrypt
import discord
from discord.ext import commands

DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "root")
DB_NAME = os.getenv("DB_NAME", "InfiniteLagrange")

DISCORD_TOKEN = os.getenv("DISCORD_TOKEN", "")
COMMAND_PREFIX = os.getenv("COMMAND_PREFIX", "!")
SESSION_DURATION = timedelta(hours=2)

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix=COMMAND_PREFIX, intents=intents)

_db_pool: Optional[aiomysql.Pool] = None


@dataclass
class LoginSession:
    username: str
    expires_at: datetime


sessions: dict[int, LoginSession] = {}


async def hash_secret(value: str) -> bytes:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None, bcrypt.hashpw, value.encode("utf-8"), bcrypt.gensalt()
    )


async def verify_secret(value: str, hashed: bytes) -> bool:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None, bcrypt.checkpw, value.encode("utf-8"), hashed
    )


async def get_pool() -> aiomysql.Pool:
    global _db_pool
    if _db_pool is None:
        _db_pool = await aiomysql.create_pool(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASSWORD,
            db=DB_NAME,
            autocommit=False,
            minsize=1,
            maxsize=10,
        )
    return _db_pool


async def fetch_user(username: str) -> Optional[dict]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.cursor(aiomysql.DictCursor) as cur:
            await cur.execute(
                "SELECT id, username, passhash FROM users WHERE username = %s",
                (username,),
            )
            return await cur.fetchone()


async def is_logged_in(user_id: int) -> Optional[LoginSession]:
    session = sessions.get(user_id)
    if not session:
        return None
    if session.expires_at < datetime.utcnow():
        sessions.pop(user_id, None)
        return None
    return session


@bot.event
async def on_ready() -> None:
    print(f"Logged in as {bot.user} (ID: {bot.user.id})")


@bot.command(name="register")
async def register(ctx: commands.Context, username: str, password: str) -> None:
    pool = await get_pool()
    hashed = await hash_secret(password)
    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT 1 FROM users WHERE username = %s", (username,))
            if await cur.fetchone():
                await ctx.send("Username already registered.")
                return
            await cur.execute(
                "SELECT 1 FROM pending_users WHERE username = %s", (username,)
            )
            if await cur.fetchone():
                await ctx.send("Registration already pending approval.")
                return
            await cur.execute(
                "INSERT INTO pending_users (username, passhash, requested_by) VALUES (%s, %s, %s)",
                (username, hashed, str(ctx.author.id)),
            )
            await conn.commit()
    await ctx.send("Registration submitted for approval.")


@bot.command(name="login")
async def login(ctx: commands.Context, username: str, password: str) -> None:
    user = await fetch_user(username)
    if not user:
        await ctx.send("No approved account found.")
        return
    stored_hash = user["passhash"]
    if isinstance(stored_hash, str):
        stored_hash = stored_hash.encode("utf-8")
    ok = await verify_secret(password, stored_hash)
    if not ok:
        await ctx.send("Invalid credentials.")
        return
    sessions[ctx.author.id] = LoginSession(
        username=username, expires_at=datetime.utcnow() + SESSION_DURATION
    )
    await ctx.send("Login successful.")


@bot.command(name="logout")
async def logout(ctx: commands.Context) -> None:
    sessions.pop(ctx.author.id, None)
    await ctx.send("Logged out.")


@bot.command(name="upload_account")
async def upload_account(
    ctx: commands.Context, game: str, game_username: str, game_password: str
) -> None:
    session = await is_logged_in(ctx.author.id)
    if not session:
        await ctx.send("Please login first.")
        return
    pool = await get_pool()
    hashed_username = await hash_secret(game_username)
    hashed_password = await hash_secret(game_password)
    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "INSERT INTO pending_game_accounts (uploader_username, game, game_username_hash, game_password_hash) "
                "VALUES (%s, %s, %s, %s)",
                (session.username, game, hashed_username, hashed_password),
            )
            await conn.commit()
    await ctx.send("Game account upload submitted for approval.")


@bot.command(name="list_accounts")
async def list_accounts(ctx: commands.Context) -> None:
    session = await is_logged_in(ctx.author.id)
    if not session:
        await ctx.send("Please login first.")
        return
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.cursor(aiomysql.DictCursor) as cur:
            await cur.execute(
                "SELECT ga.id, ga.game "
                "FROM access_grants ag "
                "JOIN game_accounts ga ON ga.id = ag.account_id "
                "WHERE ag.username = %s",
                (session.username,),
            )
            rows = await cur.fetchall()
    if not rows:
        await ctx.send("No shared accounts found.")
        return
    lines = [f"ID {row['id']}: {row['game']}" for row in rows]
    await ctx.send("Shared accounts:\n" + "\n".join(lines))


@bot.command(name="grant_access")
async def grant_access(ctx: commands.Context, account_id: int, *usernames: str) -> None:
    session = await is_logged_in(ctx.author.id)
    if not session:
        await ctx.send("Please login first.")
        return
    if not usernames:
        await ctx.send("Provide at least one username to grant access.")
        return
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT id FROM game_accounts WHERE id = %s AND uploader_username = %s",
                (account_id, session.username),
            )
            if not await cur.fetchone():
                await ctx.send("Account not found or not owned by you.")
                return
            for username in usernames:
                await cur.execute(
                    "SELECT 1 FROM users WHERE username = %s",
                    (username,),
                )
                if not await cur.fetchone():
                    await ctx.send(f"User {username} is not registered.")
                    continue
                await cur.execute(
                    "INSERT INTO access_requests (account_id, username, requested_by) VALUES (%s, %s, %s)",
                    (account_id, username, session.username),
                )
            await conn.commit()
    await ctx.send("Access requests sent. Users must confirm with !confirm_access.")


@bot.command(name="confirm_access")
async def confirm_access(ctx: commands.Context, account_id: int) -> None:
    session = await is_logged_in(ctx.author.id)
    if not session:
        await ctx.send("Please login first.")
        return
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT id, requested_by FROM access_requests WHERE account_id = %s AND username = %s",
                (account_id, session.username),
            )
            row = await cur.fetchone()
            if not row:
                await ctx.send("No pending access request found.")
                return
            await cur.execute(
                "INSERT INTO access_grants (account_id, username, granted_by) VALUES (%s, %s, %s)",
                (account_id, session.username, row[1]),
            )
            await cur.execute(
                "DELETE FROM access_requests WHERE id = %s",
                (row[0],),
            )
            await conn.commit()
    await ctx.send("Access confirmed. Ask the uploader to share the account details.")


@bot.command(name="share_account")
async def share_account(
    ctx: commands.Context,
    account_id: int,
    target_username: str,
    game_username: str,
    game_password: str,
) -> None:
    session = await is_logged_in(ctx.author.id)
    if not session:
        await ctx.send("Please login first.")
        return
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.cursor(aiomysql.DictCursor) as cur:
            await cur.execute(
                "SELECT id, game FROM game_accounts WHERE id = %s AND uploader_username = %s",
                (account_id, session.username),
            )
            account = await cur.fetchone()
            if not account:
                await ctx.send("Account not found or not owned by you.")
                return
            await cur.execute(
                "SELECT 1 FROM access_grants WHERE account_id = %s AND username = %s",
                (account_id, target_username),
            )
            if not await cur.fetchone():
                await ctx.send("User does not have confirmed access.")
                return
    recipient = discord.utils.get(ctx.guild.members, name=target_username)
    if recipient is None:
        await ctx.send("Recipient not found in this server.")
        return
    await recipient.send(
        f"Shared {account['game']} account from {session.username}:\n"
        f"Username: {game_username}\nPassword: {game_password}"
    )
    await ctx.send("Account details shared via DM.")


@bot.command(name="pending_access")
async def pending_access(ctx: commands.Context) -> None:
    session = await is_logged_in(ctx.author.id)
    if not session:
        await ctx.send("Please login first.")
        return
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.cursor(aiomysql.DictCursor) as cur:
            await cur.execute(
                "SELECT account_id FROM access_requests WHERE username = %s",
                (session.username,),
            )
            rows = await cur.fetchall()
    if not rows:
        await ctx.send("No pending access requests.")
        return
    accounts = ", ".join(str(row["account_id"]) for row in rows)
    await ctx.send(f"Pending access requests for account IDs: {accounts}")


def main() -> None:
    if not DISCORD_TOKEN:
        raise RuntimeError("DISCORD_TOKEN is not set")
    bot.run(DISCORD_TOKEN)


if __name__ == "__main__":
    main()
