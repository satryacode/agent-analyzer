# agent-analyzer

Reviews fraud verdicts produced by [agent-classifier](https://github.com/satryacode/agent-classifier), confirms or dismisses each one, blocks confirmed attackers in the database, and generates a finding report.

## Role in the System

```
agent-classifier
      │  writes FRAUDULENT verdicts → fraud_verdicts (remediated=0)
      ▼
agent-analyzer  ◄─── you are here
      │
      ├── Poll fraud_verdicts WHERE remediated=0
      ├── Review each verdict (re-evaluate evidence)
      │     ├── CONFIRMED → set remediated=1, block user in users table
      │     └── DISMISSED → set remediated=1, leave user unblocked
      └── Write finding report (JSON or Markdown)
```

## What It Must Do

### 1. Poll for unreviewed verdicts

Query the `fraud_verdicts` table for unreviewed entries:

```sql
SELECT id, source_ip, user_identity, method, path,
       confidence_score, reason, original_log_entry_reference, detected_at
FROM fraud_verdicts
WHERE remediated = 0
ORDER BY detected_at ASC;
```

### 2. Review each verdict

For each verdict, re-evaluate the evidence in `original_log_entry_reference` and the `reason` field.

Reasons produced by agent-classifier:

| Reason | Meaning |
|---|---|
| `sql_injection` | SQLi pattern matched in request body |
| `brute_force` | IP exceeded failed login threshold (default: 10) |
| `credential_stuffing` | User account exceeded failed login threshold (default: 5) |
| `scanner_detected` | Known scanner User-Agent (sqlmap, nikto, nmap, etc.) |
| `reconnaissance` | IP accessed >5 distinct paths |
| `path_enumeration` | Request to unknown/non-existent path |
| `unusual_user_agent` | Non-browser, non-curl UA on /home |
| `token_manipulation` | Multiple user identities from same IP |
| `forged_token` | 200 response on /home with no recent login |

Decision criteria (suggested):

- **Confirm** if `confidence_score >= 0.8` OR reason includes `sql_injection` or `scanner_detected`
- **Dismiss** if `confidence_score < 0.5` and only `path_enumeration` or `unusual_user_agent`
- Apply your own logic as needed

### 3. Act on confirmed verdicts

When confirmed, run both updates atomically:

```sql
-- Mark verdict as reviewed
UPDATE fraud_verdicts SET remediated = 1 WHERE id = <verdict_id>;

-- Block the user if user_identity is known
UPDATE users SET blocked = 1 WHERE username = <user_identity>;
```

Blocked users receive `403 Forbidden` from dummy-be on their next login attempt.

### 4. Mark dismissed verdicts

```sql
UPDATE fraud_verdicts SET remediated = 1 WHERE id = <verdict_id>;
-- Do NOT update users.blocked
```

### 5. Write a finding report

For each confirmed verdict, append an entry to a report file (JSON Lines or Markdown). Minimum fields:

```json
{
  "verdict_id": 42,
  "source_ip": "1.2.3.4",
  "user_identity": "alice",
  "reason": "sql_injection,scanner_detected",
  "confidence_score": 0.95,
  "action_taken": "user_blocked",
  "analyzed_at": "2026-06-10T01:00:00Z"
}
```

## DB Connection

Same PostgreSQL instance as dummy-be and agent-classifier:

```env
DB_HOST=127.0.0.1
DB_PORT=5432
DB_NAME=myapp_db
DB_USER=myapp_user
DB_PASS=your_password
```

## DB Schema Reference

```sql
-- Read from this table
fraud_verdicts (
    id                          SERIAL PRIMARY KEY,
    source_ip                   VARCHAR(45),
    user_identity               VARCHAR(255),
    method                      VARCHAR(10),
    path                        VARCHAR(500),
    confidence_score            DECIMAL(4,2),
    reason                      VARCHAR(500),   -- comma-separated reasons
    original_log_entry_reference TEXT,          -- raw JSON log line
    detected_at                 TIMESTAMP,
    remediated                  SMALLINT        -- 0 = pending, 1 = reviewed
)

-- Update this table to block users
users (
    id          SERIAL PRIMARY KEY,
    username    VARCHAR(255),
    email       VARCHAR(255),
    password    VARCHAR(255),
    created_at  TIMESTAMP,
    blocked     SMALLINT DEFAULT 0  -- 0 = active, 1 = blocked
)
```

## Expected Behavior

- Runs as a polling loop or one-shot job
- Processes only `remediated=0` rows — never re-reviews the same verdict twice
- Always sets `remediated=1` after review, whether confirmed or dismissed
- Blocking a user is irreversible by this service — unblocking requires manual DB update
- Report file grows over time; each run appends new findings

## Verify It's Working

```bash
# Check how many verdicts are pending review
PGPASSWORD=your_password psql -h 127.0.0.1 -U myapp_user -d myapp_db \
  -c "SELECT COUNT(*) FROM fraud_verdicts WHERE remediated=0;"

# Check blocked users
PGPASSWORD=your_password psql -h 127.0.0.1 -U myapp_user -d myapp_db \
  -c "SELECT username, blocked FROM users WHERE blocked=1;"

# Check all reviewed verdicts
PGPASSWORD=your_password psql -h 127.0.0.1 -U myapp_user -d myapp_db \
  -c "SELECT source_ip, reason, confidence_score, remediated FROM fraud_verdicts ORDER BY detected_at DESC LIMIT 20;"
```
