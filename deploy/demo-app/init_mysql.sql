USE inventory;

CREATE TABLE IF NOT EXISTS products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    sku VARCHAR(50) UNIQUE NOT NULL,
    price DECIMAL(10, 2) NOT NULL DEFAULT 0,
    stock INT NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Seed inventory data
INSERT IGNORE INTO products (name, sku, price, stock) VALUES
    ('Widget', 'WDG-001', 19.99, 100),
    ('Gadget', 'GDG-001', 49.99, 50),
    ('Sprocket', 'SPR-001', 9.99, 200),
    ('Gizmo', 'GZM-001', 29.99, 75),
    ('Doohickey', 'DHK-001', 14.99, 150);
