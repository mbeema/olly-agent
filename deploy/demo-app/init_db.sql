CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100),
    email VARCHAR(100),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Grant permissions to demo user (needed for pg_hba.conf md5 auth)
GRANT ALL PRIVILEGES ON TABLE users TO demo;
GRANT USAGE, SELECT ON SEQUENCE users_id_seq TO demo;

INSERT INTO users (name, email) VALUES ('Alice', 'alice@example.com') ON CONFLICT DO NOTHING;
INSERT INTO users (name, email) VALUES ('Bob', 'bob@example.com') ON CONFLICT DO NOTHING;

-- Orders table (queried by Go order-service)
CREATE TABLE IF NOT EXISTS orders (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    product VARCHAR(200),
    amount DECIMAL(10, 2),
    created_at TIMESTAMP DEFAULT NOW()
);

GRANT ALL PRIVILEGES ON TABLE orders TO demo;
GRANT USAGE, SELECT ON SEQUENCE orders_id_seq TO demo;

INSERT INTO orders (user_id, product, amount) VALUES (1, 'Widget', 19.99) ON CONFLICT DO NOTHING;
INSERT INTO orders (user_id, product, amount) VALUES (2, 'Gadget', 49.99) ON CONFLICT DO NOTHING;
