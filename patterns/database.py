"""
SecretSweep — Database & Infrastructure Patterns

Patterns for database connection strings, SSH/PEM private keys, and
infrastructure credentials. These are extremely common in .env files,
docker-compose configs, and code snippets that users paste into LLM chats.

Pattern design notes:
- Connection strings are the most complex patterns here because they combine
  a URL scheme, credentials, host, and database name in one string.
- We use non-greedy matching for passwords in connection strings to avoid
  over-capturing into the host portion.
- Private key detection is structural (BEGIN/END markers) and very reliable.
- .env password patterns rely heavily on context (variable name) because
  the values themselves have no distinctive format.
"""

import re

from .registry import SecretPattern, register

# ===================================================
# DATABASE CONNECTION STRINGS
# ===================================================

POSTGRES_CONNECTION_STRING = SecretPattern(
    id="postgres_connection_string",
    name="PostgreSQL Connection String (with password)",
    description=(
        "PostgreSQL connection URI containing embedded credentials."
        " Format: postgres://user:password@host:port/database"
    ),
    provider="postgresql",
    severity="high",
    regex=re.compile(
        r"(?P<secret>"
        r"postgres(?:ql)?://"
        r"[^:@\s]{1,64}"     # username
        r":"
        r"[^@\s]{1,128}"    # password (non-greedy up to @)
        r"@"
        r"[^/\s]{1,256}"    # host:port
        r"(?:/[^\s\"']{0,128})?"  # optional /database
        r")",
        re.ASCII
    ),
    confidence_base=0.92,
    entropy_threshold=0.0,
    context_keywords=[
        "database", "DATABASE_URL", "postgres", "postgresql", "db", "connection",
    ],
    known_test_values={
        "postgres://user:password@localhost:5432/mydb",
        "postgresql://postgres:postgres@localhost/test",
    },
    recommendation=(
        "Rotate the database password immediately."
        " Use a secrets manager (e.g., AWS Secrets Manager, Vault, Doppler)"
        " to inject credentials at runtime instead of embedding them"
        " in connection strings."
    ),
    tags=["database", "postgresql"],
)


MYSQL_CONNECTION_STRING = SecretPattern(
    id="mysql_connection_string",
    name="MySQL Connection String (with password)",
    description="MySQL connection URI containing embedded credentials.",
    provider="mysql",
    severity="high",
    regex=re.compile(
        r"(?P<secret>"
        r"mysql(?:\+pymysql|\+mysqlconnector)?://"
        r"[^:@\s]{1,64}"     # username
        r":"
        r"[^@\s]{1,128}"    # password
        r"@"
        r"[^/\s]{1,256}"    # host:port
        r"(?:/[^\s\"']{0,128})?"  # optional /database
        r")",
        re.ASCII
    ),
    confidence_base=0.92,
    entropy_threshold=0.0,
    context_keywords=[
        "database", "DATABASE_URL", "mysql", "db", "connection",
    ],
    known_test_values={
        "mysql://root:password@localhost:3306/mydb",
        "mysql://user:pass@localhost/test",
    },
    recommendation=(
        "Rotate the database password."
        " Use a secrets manager for credential injection."
    ),
    tags=["database", "mysql"],
)


MONGODB_CONNECTION_STRING = SecretPattern(
    id="mongodb_connection_string",
    name="MongoDB Connection String (with password)",
    description=(
        "MongoDB connection URI containing embedded credentials."
        " Matches both mongodb:// and mongodb+srv:// schemes."
    ),
    provider="mongodb",
    severity="high",
    regex=re.compile(
        r"(?P<secret>"
        r"mongodb(?:\+srv)?://"
        r"[^:@\s]{1,64}"     # username
        r":"
        r"[^@\s]{1,128}"    # password
        r"@"
        r"[^\s\"']{1,512}"  # host(s) + options (MongoDB can have multiple hosts)
        r")",
        re.ASCII
    ),
    confidence_base=0.92,
    entropy_threshold=0.0,
    context_keywords=[
        "mongo", "mongodb", "MONGODB_URI", "MONGO_URL", "database", "atlas",
    ],
    known_test_values={
        "mongodb://user:password@localhost:27017/mydb",
        "mongodb+srv://user:pass@cluster0.example.mongodb.net/test",
    },
    recommendation=(
        "Rotate the database password in your MongoDB instance"
        " or Atlas dashboard."
        " Use environment variables or a secrets manager."
    ),
    tags=["database", "mongodb"],
)


REDIS_CONNECTION_STRING = SecretPattern(
    id="redis_connection_string",
    name="Redis Connection String (with password)",
    description="Redis connection URI containing embedded credentials.",
    provider="redis",
    severity="high",
    regex=re.compile(
        r"(?P<secret>"
        r"redis(?:s)?://"
        r"(?:[^:@\s]{0,64}:)?"   # optional username:
        r"[^@\s]{1,128}"          # password
        r"@"
        r"[^/\s]{1,256}"          # host:port
        r"(?:/[0-9]{1,2})?"       # optional /db_number
        r")",
        re.ASCII
    ),
    confidence_base=0.90,
    entropy_threshold=0.0,
    context_keywords=["redis", "REDIS_URL", "cache", "REDIS_PASSWORD"],
    known_test_values={
        "redis://:password@localhost:6379/0",
        "redis://default:pass@localhost:6379",
    },
    recommendation=(
        "Rotate the Redis password."
        " Use ACLs and TLS for production Redis instances."
    ),
    tags=["database", "redis"],
)


PASSWORD_IN_URL = SecretPattern(
    id="password_in_url",
    name="Password Embedded in URL",
    description=(
        "Generic URL with embedded user:password credentials."
        " Catches database URLs, API endpoints, and service connections"
        " not covered by specific patterns."
    ),
    provider="generic",
    severity="high",
    regex=re.compile(
        r"(?P<secret>"
        r"(?:https?|ftp|amqps?|kafka)://"
        r"[^:@\s]{1,64}"     # username
        r":"
        r"[^@\s]{3,128}"    # password (min 3 chars to reduce false positives)
        r"@"
        r"[^/\s]{1,256}"    # host
        r")",
        re.ASCII
    ),
    confidence_base=0.80,
    entropy_threshold=2.0,  # filter out trivially simple passwords like "x"
    context_keywords=[
        "url", "connection", "endpoint", "password", "credential",
    ],
    known_test_values={
        "https://user:password@example.com",
        "http://admin:admin@localhost",
    },
    recommendation=(
        "Remove embedded credentials from the URL."
        " Use authentication headers or environment variables instead."
    ),
    tags=["database", "generic", "url"],
)


# ===================================================
# .ENV FILE PATTERNS
# ===================================================

ENV_DATABASE_PASSWORD = SecretPattern(
    id="env_database_password",
    name="Database Password in Environment Variable",
    description=(
        "Database password assigned in an .env file or shell export."
        " Matches common variable names like DB_PASSWORD,"
        " DATABASE_PASSWORD, MYSQL_ROOT_PASSWORD, POSTGRES_PASSWORD."
    ),
    provider="generic",
    severity="high",
    regex=re.compile(
        r"(?P<context_key>"
        r"(?:DB_PASSWORD|DATABASE_PASSWORD|MYSQL_ROOT_PASSWORD|MYSQL_PASSWORD"
        r"|POSTGRES_PASSWORD|PGPASSWORD|MONGO_PASSWORD|REDIS_PASSWORD)"
        r")"
        r"[\s]*[=][\s]*[\"']?"
        r"(?P<secret>[^\s\"'#]{3,128})"  # min 3 chars, stop at whitespace/quotes/comments
        r"[\"']?",
        re.ASCII | re.IGNORECASE
    ),
    confidence_base=0.88,
    entropy_threshold=1.5,  # catch even simple passwords since context is strong
    context_keywords=["password", "database", "db", "env"],
    known_test_values={
        "password",
        "changeme",
        "secret",
        "example",
        "your_password_here",
        "REPLACE_ME",
    },
    recommendation=(
        "Move this password to a secrets manager."
        " Never commit .env files containing real credentials."
    ),
    tags=["database", "env", "password"],
)


# ===================================================
# PRIVATE KEYS
# ===================================================

SSH_PRIVATE_KEY = SecretPattern(
    id="ssh_private_key",
    name="SSH/RSA/EC Private Key",
    description=(
        "PEM-encoded private key block. Matches RSA, EC, DSA,"
        " ED25519, and generic PRIVATE KEY markers."
    ),
    provider="generic",
    severity="critical",
    regex=re.compile(
        r"(?P<secret>"
        r"-----BEGIN\s"
        r"(?:RSA\s|EC\s|DSA\s|OPENSSH\s|ENCRYPTED\s)?"
        r"PRIVATE\sKEY-----"
        r"[\s\S]{50,5000}?"  # key body, non-greedy, reasonable bounds
        r"-----END\s"
        r"(?:RSA\s|EC\s|DSA\s|OPENSSH\s|ENCRYPTED\s)?"
        r"PRIVATE\sKEY-----"
        r")",
        re.DOTALL
    ),
    confidence_base=0.98,
    entropy_threshold=0.0,  # structural match, no entropy check needed
    context_keywords=["key", "private", "ssh", "pem", "rsa", "id_rsa"],
    known_test_values=set(),
    recommendation=(
        "Revoke this key immediately. Generate a new key pair and distribute"
        " the new public key to all systems that accepted the old one."
        " If this is an SSH key, remove it from ~/.ssh/authorized_keys"
        " on all servers."
    ),
    tags=["infrastructure", "ssh", "key"],
)


register(
    POSTGRES_CONNECTION_STRING,
    MYSQL_CONNECTION_STRING,
    MONGODB_CONNECTION_STRING,
    REDIS_CONNECTION_STRING,
    PASSWORD_IN_URL,
    ENV_DATABASE_PASSWORD,
    SSH_PRIVATE_KEY,
)
