import asyncio
import getpass
import os
from typing import List

import aiomysql
import bcrypt

DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "root")
DB_NAME = os.getenv("DB_NAME", "InfiniteLagrange")

MASTER_PASSWORD_HASH = os.getenv(
    "MASTER_PASSWORD_HASH",
    "$2b$12$s2hZElYg6u0uXAn1scV73eG4AopXwTgZODGJ5Y0dPc2Ugt2uT9j7C",
)


async def verify_master_password() -> None:
    password = getpass.getpass("Master password: ")
    stored_hash = MASTER_PASSWORD_HASH.encode("utf-8")
    if not bcrypt.checkpw(password.encode("utf-8"), stored_hash):
        raise SystemExit("Invalid master password.")


def prompt_ids(prompt: str) -> List[int]:
    raw = input(prompt).strip()
    if not raw:
        return []
    return [int(item) for item in raw.split(",") if item.strip().isdigit()]


def build_in_clause(values: List[int]) -> str:
    placeholders = ", ".join(["%s"] * len(values))
    return f"({placeholders})"


async def approve_pending_users(pool: aiomysql.Pool) -> None:
    async with pool.acquire() as conn:
        async with conn.cursor(aiomysql.DictCursor) as cur:
            await cur.execute(
                "SELECT id, username, requested_by, created_at FROM pending_users ORDER BY created_at"
            )
            rows = await cur.fetchall()
            if not rows:
                print("No pending user registrations.")
                return
            print("Pending user registrations:")
            for row in rows:
                print(
                    f"  ID {row['id']}: {row['username']} requested by {row['requested_by']}"
                )
            approve_ids = prompt_ids("Approve user IDs (comma-separated): ")
            reject_ids = prompt_ids("Reject user IDs (comma-separated): ")
            if approve_ids:
                approve_clause = build_in_clause(approve_ids)
                await cur.execute(
                    "INSERT INTO users (username, passhash) "
                    f"SELECT username, passhash FROM pending_users WHERE id IN {approve_clause}",
                    approve_ids,
                )
                await cur.execute(
                    f"DELETE FROM pending_users WHERE id IN {approve_clause}",
                    approve_ids,
                )
            if reject_ids:
                reject_clause = build_in_clause(reject_ids)
                await cur.execute(
                    f"DELETE FROM pending_users WHERE id IN {reject_clause}",
                    reject_ids,
                )
            await conn.commit()


async def approve_pending_accounts(pool: aiomysql.Pool) -> None:
    async with pool.acquire() as conn:
        async with conn.cursor(aiomysql.DictCursor) as cur:
            await cur.execute(
                "SELECT id, uploader_username, game, created_at FROM pending_game_accounts ORDER BY created_at"
            )
            rows = await cur.fetchall()
            if not rows:
                print("No pending game account uploads.")
                return
            print("Pending game account uploads:")
            for row in rows:
                print(
                    f"  ID {row['id']}: {row['game']} uploaded by {row['uploader_username']}"
                )
            approve_ids = prompt_ids("Approve account IDs (comma-separated): ")
            reject_ids = prompt_ids("Reject account IDs (comma-separated): ")
            if approve_ids:
                approve_clause = build_in_clause(approve_ids)
                await cur.execute(
                    "INSERT INTO game_accounts (uploader_username, game, game_username_hash, game_password_hash) "
                    "SELECT uploader_username, game, game_username_hash, game_password_hash "
                    f"FROM pending_game_accounts WHERE id IN {approve_clause}",
                    approve_ids,
                )
                await cur.execute(
                    f"DELETE FROM pending_game_accounts WHERE id IN {approve_clause}",
                    approve_ids,
                )
            if reject_ids:
                reject_clause = build_in_clause(reject_ids)
                await cur.execute(
                    f"DELETE FROM pending_game_accounts WHERE id IN {reject_clause}",
                    reject_ids,
                )
            await conn.commit()


async def main() -> None:
    await verify_master_password()
    pool = await aiomysql.create_pool(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        db=DB_NAME,
        autocommit=False,
        minsize=1,
        maxsize=5,
    )
    try:
        await approve_pending_users(pool)
        await approve_pending_accounts(pool)
    finally:
        pool.close()
        await pool.wait_closed()


if __name__ == "__main__":
    asyncio.run(main())
