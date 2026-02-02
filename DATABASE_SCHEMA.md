# Required Database and Tables

**Database name:** `InfiniteLagrange`

## Tables

```sql
CREATE TABLE users (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(64) NOT NULL UNIQUE,
  passhash VARBINARY(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE pending_users (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(64) NOT NULL UNIQUE,
  passhash VARBINARY(255) NOT NULL,
  requested_by VARCHAR(64) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE pending_game_accounts (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  uploader_username VARCHAR(64) NOT NULL,
  game VARCHAR(128) NOT NULL,
  game_username_hash VARBINARY(255) NOT NULL,
  game_password_hash VARBINARY(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE game_accounts (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  uploader_username VARCHAR(64) NOT NULL,
  game VARCHAR(128) NOT NULL,
  game_username_hash VARBINARY(255) NOT NULL,
  game_password_hash VARBINARY(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE access_requests (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  account_id BIGINT NOT NULL,
  username VARCHAR(64) NOT NULL,
  requested_by VARCHAR(64) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE access_grants (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  account_id BIGINT NOT NULL,
  username VARCHAR(64) NOT NULL,
  granted_by VARCHAR(64) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Notes
- `users` holds approved logins only.
- `pending_users` is reviewed by the approval console before users are inserted into `users`.
- `pending_game_accounts` stores uploaded game credentials awaiting approval by the approval console.
- `game_accounts` stores approved game credentials (hashed only).
- `access_requests` tracks uploader-initiated access requests that require user confirmation via Discord.
- `access_grants` tracks confirmed access so the uploader can share the account details via Discord DM.
