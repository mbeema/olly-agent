CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100),
    email VARCHAR(100),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Grant permissions to demo user (needed for pg_hba.conf md5 auth)
GRANT ALL PRIVILEGES ON TABLE users TO demo;
GRANT USAGE, SELECT ON SEQUENCE users_id_seq TO demo;

INSERT INTO users (name, email) VALUES ('Alice', 'alice@example.com');
INSERT INTO users (name, email) VALUES ('Bob', 'bob@example.com');
