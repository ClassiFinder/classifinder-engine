"""
ClassiFinder — Database & Infrastructure Patterns

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
    # Source: PostgreSQL libpq connection URI specification.
    #   https://www.postgresql.org/docs/current/libpq-connect.html#LIBPQ-CONNSTRING
    regex=re.compile(
        r"(?P<secret>"
        r"postgres(?:ql)?://"
        r"[^:@\s]{1,64}"  # username
        r":"
        r"[^@\s]{1,128}"  # password (non-greedy up to @)
        r"@"
        r"[^/\s]{1,256}"  # host:port
        r"(?:/[^\s\"']{0,128})?"  # optional /database
        r")",
        re.ASCII,
    ),
    confidence_base=0.92,
    entropy_threshold=0.0,
    context_keywords=[
        "database",
        "DATABASE_URL",
        "postgres",
        "postgresql",
        "db",
        "connection",
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
    # Source: MySQL Connector URI specification (mysql:// scheme).
    #   https://dev.mysql.com/doc/refman/8.0/en/connecting-using-uri-or-key-value-pairs.html
    # +pymysql / +mysqlconnector dialect prefixes are SQLAlchemy convention.
    regex=re.compile(
        r"(?P<secret>"
        r"mysql(?:\+pymysql|\+mysqlconnector)?://"
        r"[^:@\s]{1,64}"  # username
        r":"
        r"[^@\s]{1,128}"  # password
        r"@"
        r"[^/\s]{1,256}"  # host:port
        r"(?:/[^\s\"']{0,128})?"  # optional /database
        r")",
        re.ASCII,
    ),
    confidence_base=0.92,
    entropy_threshold=0.0,
    context_keywords=[
        "database",
        "DATABASE_URL",
        "mysql",
        "db",
        "connection",
    ],
    known_test_values={
        "mysql://root:password@localhost:3306/mydb",
        "mysql://user:pass@localhost/test",
    },
    recommendation=(
        "Rotate the database password. Use a secrets manager for credential injection."
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
    # Connection string format per the official MongoDB URI spec:
    #   https://www.mongodb.com/docs/manual/reference/connection-string-formats/
    # "mongodb://" and "mongodb+srv://" are vendor-defined URI schemes.
    # Independently composed from the spec.
    regex=re.compile(
        r"(?P<secret>"
        r"mongodb(?:\+srv)?://"
        r"[^:@\s]{1,64}"  # username
        r":"
        r"[^@\s]{1,128}"  # password
        r"@"
        r"[^\s\"']{1,512}"  # host(s) + options (MongoDB can have multiple hosts)
        r")",
        re.ASCII,
    ),
    confidence_base=0.92,
    entropy_threshold=0.0,
    context_keywords=[
        "mongo",
        "mongodb",
        "MONGODB_URI",
        "MONGO_URL",
        "database",
        "atlas",
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
    # Source: IANA URI scheme registry (redis, rediss).
    #   https://www.iana.org/assignments/uri-schemes/prov/redis
    #   https://www.iana.org/assignments/uri-schemes/prov/rediss
    # rediss:// is the Redis-over-TLS variant. Independently composed from the registration.
    regex=re.compile(
        r"(?P<secret>"
        r"redis(?:s)?://"
        r"(?:[^:@\s]{0,64}:)?"  # optional username:
        r"[^@\s]{1,128}"  # password
        r"@"
        r"[^/\s]{1,256}"  # host:port
        r"(?:/[0-9]{1,2})?"  # optional /db_number
        r")",
        re.ASCII,
    ),
    confidence_base=0.90,
    entropy_threshold=0.0,
    context_keywords=["redis", "REDIS_URL", "cache", "REDIS_PASSWORD"],
    known_test_values={
        "redis://:password@localhost:6379/0",
        "redis://default:pass@localhost:6379",
    },
    recommendation=("Rotate the Redis password. Use ACLs and TLS for production Redis instances."),
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
    # Format per RFC 3986 (URI generic syntax) — userinfo = user:password@.
    #   https://datatracker.ietf.org/doc/html/rfc3986#section-3.2.1
    regex=re.compile(
        r"(?P<secret>"
        r"(?:https?|ftp|amqps?|kafka)://"
        r"[^:@\s]{1,64}"  # username
        r":"
        r"[^@\s]{3,128}"  # password (min 3 chars to reduce false positives)
        r"@"
        r"[^/\s]{1,256}"  # host
        r")",
        re.ASCII,
    ),
    confidence_base=0.80,
    entropy_threshold=2.0,  # filter out trivially simple passwords like "x"
    context_keywords=[
        "url",
        "connection",
        "endpoint",
        "password",
        "credential",
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
    # Independently authored — common .env / shell-export variable names for
    # database password assignment. Names sourced from the official Docker
    # images (postgres, mysql, mongo, redis) and PostgreSQL libpq env vars.
    regex=re.compile(
        r"(?P<context_key>"
        r"(?:DB_PASSWORD|DATABASE_PASSWORD|MYSQL_ROOT_PASSWORD|MYSQL_PASSWORD"
        r"|POSTGRES_PASSWORD|PGPASSWORD|MONGO_PASSWORD|REDIS_PASSWORD)"
        r")"
        r"[\s]*[=][\s]*[\"']?"
        r"(?P<secret>[^\s\"'#]{3,128})"  # min 3 chars, stop at whitespace/quotes/comments
        r"[\"']?",
        re.ASCII | re.IGNORECASE,
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
    # Format per RFC 7468 (textual encodings of PKIX, PKCS, and CMS structures)
    #   https://datatracker.ietf.org/doc/html/rfc7468
    # plus the OpenSSH-specific BEGIN OPENSSH PRIVATE KEY marker (PROTOCOL.key).
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
        re.DOTALL,
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


PGP_PRIVATE_KEY = SecretPattern(
    id="pgp_private_key",
    name="PGP Private Key Block",
    description=(
        "OpenPGP private key block delimited by the ASCII-armor"
        " '-----BEGIN PGP PRIVATE KEY BLOCK-----' / '-----END ...-----' markers."
        " A leaked PGP private key allows decryption and signing as its owner."
    ),
    provider="pgp",
    severity="critical",
    # Source: https://www.rfc-editor.org/rfc/rfc4880  (OpenPGP armor headers, RFC 4880 §6.2)
    regex=re.compile(
        r"(?P<secret>-----BEGIN PGP PRIVATE KEY BLOCK-----"
        r"[\s\S]{50,}?"
        r"-----END PGP PRIVATE KEY BLOCK-----)",
        re.DOTALL,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,  # structural match, no entropy check needed
    context_keywords=["pgp", "gpg", "private", "key", "openpgp"],
    known_test_values={
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\n"
        "AbCdEfGhIjKlMnOp\nAbCdEfGhIjKlMnOp\nAbCdEfGhIjKlMnOp\n"
        "AbCdEfGhIjKlMnOp\nAbCdEfGhIjKlMnOp\n"
        "-----END PGP PRIVATE KEY BLOCK-----",
    },
    recommendation=(
        "Revoke this PGP key by publishing a revocation certificate, then generate"
        " a new key pair and distribute the new public key to your correspondents."
    ),
    tags=["infrastructure", "pgp", "key"],
)


# ===================================================
# SUPABASE
# ===================================================

SUPABASE_SERVICE_KEY = SecretPattern(
    id="supabase_service_key",
    name="Supabase Service Role Key",
    description=(
        "Supabase service role key — a JWT with the standard HS256 header"
        " (eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9) detected by Supabase context."
        " Bypasses Row Level Security and grants full database access."
    ),
    provider="supabase",
    severity="critical",
    # Vendor-published env var names per Supabase Dashboard > API:
    #   https://supabase.com/docs/guides/api/api-keys
    # JWT format (eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.X.Y) per RFC 7519.
    regex=re.compile(
        r"(?:"
        r"(?:SUPABASE_SERVICE_ROLE_KEY|SUPABASE_KEY|SUPABASE_SECRET|supabase.*service.*key|supabase.*token)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{20,500}\.[A-Za-z0-9_-]{20,500})"
        r"(?![A-Za-z0-9_\-.])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.92,
    entropy_threshold=0.0,
    context_keywords=[
        "supabase",
        "SUPABASE_SERVICE_ROLE_KEY",
        "SUPABASE_KEY",
        "supabase_url",
        "service_role",
    ],
    known_test_values=set(),
    recommendation=(
        "Rotate this key in the Supabase Dashboard under Settings > API."
        " The service role key bypasses RLS — never expose it client-side."
    ),
    tags=["database", "supabase", "auth"],
)


# ===================================================
# RABBITMQ
# ===================================================

RABBITMQ_CONNECTION_STRING = SecretPattern(
    id="rabbitmq_connection_string",
    name="RabbitMQ Connection String (with credentials)",
    description=(
        "RabbitMQ connection URI containing embedded credentials."
        " Format: amqp://user:password@host:port/vhost"
        " or amqps:// for TLS connections."
    ),
    provider="rabbitmq",
    severity="high",
    # Source: IANA URI scheme registrations for amqp and amqps.
    #   https://www.iana.org/assignments/uri-schemes/prov/amqp
    #   https://www.iana.org/assignments/uri-schemes/prov/amqps
    regex=re.compile(
        r"(?P<secret>"
        r"amqps?://"
        r"[^:@\s\"']{1,64}"   # username
        r":"
        r"[^@\s\"']{1,128}"   # password
        r"@"
        r"[^\s\"']{1,256}"    # host[:port][/vhost]
        r")",
        re.ASCII,
    ),
    confidence_base=0.92,
    entropy_threshold=0.0,
    context_keywords=["rabbitmq", "amqp", "RABBITMQ_URL", "AMQP_URL", "broker"],
    known_test_values={
        "amqp://user:password@localhost:5672/vhost",
        "amqps://admin:pass@localhost/",
    },
    recommendation=(
        "Rotate the RabbitMQ credentials."
        " Use a secrets manager to inject credentials at runtime"
        " instead of embedding them in connection strings."
    ),
    tags=["database", "rabbitmq", "messaging"],
)


# ===================================================
# JDBC
# ===================================================

JDBC_CONNECTION_STRING = SecretPattern(
    id="jdbc_connection_string",
    name="JDBC Connection String (with credentials)",
    description=(
        "JDBC connection URL containing embedded credentials."
        " Matches both user:password@host format and ?password= / ;password= query params."
    ),
    provider="jdbc",
    severity="high",
    # Source: Java JDBC URL specification (JDBC 4.3, JSR 221).
    regex=re.compile(
        r"(?P<secret>"
        r"jdbc:[a-z][a-z0-9+\-_:]*://"
        r"(?:"
        r"[^:@\s\"']{1,64}:[^@\s\"']{3,128}@[^\s\"']{1,256}"
        r"|"
        r"[^\s\"']*[?;](?:[^\s\"'&;=]*&)?(?:password|passwd)=[^\s\"'&;]+"
        r")"
        r")",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.88,
    entropy_threshold=0.0,
    context_keywords=["jdbc", "datasource", "JDBC_URL", "db_url", "database"],
    known_test_values={
        "jdbc:mysql://root:password@localhost:3306/mydb",
        "jdbc:postgresql://user:pass@localhost:5432/testdb",
        "jdbc:oracle:thin:@//localhost:1521/orcl?password=secret",
    },
    recommendation=(
        "Remove embedded credentials from JDBC URLs."
        " Use a secrets manager or connection pool with credential injection."
    ),
    tags=["database", "jdbc", "java"],
)


# ===================================================
# COUCHBASE
# ===================================================

COUCHBASE_CONNECTION_STRING = SecretPattern(
    id="couchbase_connection_string",
    name="Couchbase Connection String (with credentials)",
    description=(
        "Couchbase connection URI containing embedded credentials."
        " Format: couchbase://user:password@host or couchbases:// for TLS."
    ),
    provider="couchbase",
    severity="high",
    # Source: Couchbase SDK connection string specification.
    #   https://docs.couchbase.com/sdk-api/couchbase-c-client/md_doc_connstr.html
    regex=re.compile(
        r"(?P<secret>"
        r"couchbases?://"
        r"[^:@\s\"']{1,64}"   # username
        r":"
        r"[^@\s\"']{1,128}"   # password
        r"@"
        r"[^\s\"']{1,256}"    # host[:port]
        r")",
        re.ASCII,
    ),
    confidence_base=0.92,
    entropy_threshold=0.0,
    context_keywords=["couchbase", "couchbases", "COUCHBASE_URL", "bucket"],
    known_test_values={
        "couchbase://user:password@localhost",
        "couchbases://admin:secret@cluster.example.com",
    },
    recommendation=(
        "Rotate the Couchbase credentials."
        " Use Couchbase Vault integration or a secrets manager for credential injection."
    ),
    tags=["database", "couchbase"],
)


# ===================================================
# NEON (Batch 10 — 2026-07-06)
# ===================================================

NEON_API_KEY = SecretPattern(
    id="neon_api_key",
    name="Neon API Key",
    description=(
        "Neon (serverless Postgres) API key. Neon issues account, organization,"
        " and project-scoped keys with 'neon_api_key_', 'neon_org_key_', and"
        " 'neon_project_key_' prefixes followed by an alphanumeric body. Prefix-"
        " anchored; grants management access to Neon projects, branches, and"
        " connection details."
    ),
    provider="neon",
    severity="high",
    # Format per https://neon.com/docs/manage/api-keys : keys use documented,
    # example-backed prefixes neon_api_key_ / neon_org_key_ / neon_project_key_
    # followed by an alphanumeric body (example body ~32 chars). Regex
    # independently authored from the vendor docs. confidence_base 0.90.
    # Format per https://neon.com/docs/manage/api-keys
    regex=re.compile(
        r"neon_(?:api_key|org_key|project_key)_"
        r"(?P<secret>[A-Za-z0-9]{24,64})"
        r"(?![A-Za-z0-9])",
        re.ASCII,
    ),
    confidence_base=0.90,
    entropy_threshold=0.0,
    context_keywords=["neon", "neon.tech", "NEON_API_KEY", "serverless"],
    known_test_values={
        # The captured secret is the body after the neon_<scope>_key_ prefix.
        # Synthetic; concatenated so no scannable secret literal exists in source.
        "AbCdEfGhIjKlMnOpQrStUvWx" + "0123456789",
    },
    recommendation=(
        "Revoke this key in the Neon console under Account Settings > API keys"
        " and issue a replacement for the integration that used it."
    ),
    tags=["database", "neon", "postgres"],
)


# ===================================================
# DATASTAX ASTRA DB (Batch 12 — 2026-07-13; prefix-anchored)
# ===================================================

ASTRA_DB_APPLICATION_TOKEN = SecretPattern(
    id="astra_db_application_token",
    name="DataStax Astra DB Application Token",
    description=(
        "DataStax Astra DB application token — the literal 'AstraCS:' prefix, a"
        " 24-character client-id segment, a ':' separator, and a 64-character"
        " lowercase-hex secret. Grants database and administration access to the"
        " Astra DB organization at the token's role scope. Prefix-anchored on"
        " 'AstraCS:'."
    ),
    provider="datastax",
    severity="critical",
    # Source: https://docs.datastax.com/en/astra-db-serverless/administration/manage-application-tokens.html
    # (DataStax Astra DB docs — application tokens have the form
    # 'AstraCS:<clientId>:<secret>', with a concrete example in the doc).
    # Independently authored — 'AstraCS:' prefix + 24-char id + ':' + 64 hex.
    regex=re.compile(
        r"(?P<secret>AstraCS:[A-Za-z0-9]{24}:[a-f0-9]{64})(?![a-f0-9])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=3.0,
    context_keywords=[
        "astra",
        "AstraCS",
        "datastax",
        "astra_db",
        "ASTRA_DB_APPLICATION_TOKEN",
    ],
    known_test_values={
        # Synthetic — fixed 'A'*24 id + sequential-hex secret, concatenated.
        # Down-scores to ~0.15.
        "AstraCS:" + "A" * 24 + ":" + "0123456789abcdef" * 4,
    },
    recommendation=(
        "Revoke this token in the Astra DB console under Settings > Token"
        " Management and issue a replacement for the application that used it."
    ),
    tags=["database", "datastax", "cassandra"],
)


register(
    POSTGRES_CONNECTION_STRING,
    MYSQL_CONNECTION_STRING,
    MONGODB_CONNECTION_STRING,
    REDIS_CONNECTION_STRING,
    PASSWORD_IN_URL,
    ENV_DATABASE_PASSWORD,
    SSH_PRIVATE_KEY,
    # Batch 8 — vendor-sourced patterns (2026-06-22)
    PGP_PRIVATE_KEY,
    SUPABASE_SERVICE_KEY,
    RABBITMQ_CONNECTION_STRING,
    JDBC_CONNECTION_STRING,
    COUCHBASE_CONNECTION_STRING,
    # Batch 10 — vendor-sourced patterns (2026-07-06)
    NEON_API_KEY,
    # Batch 12 — vendor-sourced patterns (2026-07-13)
    ASTRA_DB_APPLICATION_TOKEN,
)
