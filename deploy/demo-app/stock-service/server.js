// Node.js stock-service for cross-language tracing demo.
// Express + Redis (cache) + PostgreSQL (order count enrichment).
// Leaf service in the 4-hop chain: Python → Java → .NET → Node.js → Redis + PostgreSQL

const express = require('express');
const { createClient } = require('redis');
const { Pool } = require('pg');

const PORT = parseInt(process.env.PORT || '8083', 10);
const REDIS_HOST = process.env.REDIS_HOST || 'localhost';
const REDIS_PORT = parseInt(process.env.REDIS_PORT || '6379', 10);

const app = express();
app.use(express.json());

// Redis client
const redisClient = createClient({
    socket: { host: REDIS_HOST, port: REDIS_PORT }
});
redisClient.on('error', (err) => console.error('Redis error:', err));

// PostgreSQL pool
const pgPool = new Pool({
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '5432', 10),
    database: process.env.DB_NAME || 'demo',
    user: process.env.DB_USER || 'demo',
    password: process.env.DB_PASSWORD || 'demo123',
    max: 5,
});

// In-memory stock data (matches inventory SKUs)
const stockData = {
    'WDG-001': { sku: 'WDG-001', name: 'Premium Widget', quantity: 150, warehouse: 'US-WEST' },
    'GDG-001': { sku: 'GDG-001', name: 'Standard Gadget', quantity: 75, warehouse: 'US-EAST' },
    'SPR-001': { sku: 'SPR-001', name: 'Super Sprocket', quantity: 200, warehouse: 'US-WEST' },
    'GZM-001': { sku: 'GZM-001', name: 'Mega Gizmo', quantity: 30, warehouse: 'EU-CENTRAL' },
    'DHK-001': { sku: 'DHK-001', name: 'Doohickey Pro', quantity: 90, warehouse: 'US-EAST' },
};

app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', service: 'stock-service' });
});

app.get('/api/stock', (req, res) => {
    res.json(Object.values(stockData));
});

app.get('/api/stock/:sku', async (req, res) => {
    const sku = req.params.sku.toUpperCase();
    const stock = stockData[sku];
    if (!stock) {
        return res.status(404).json({ error: 'stock not found', sku });
    }

    const cacheKey = `stock:${sku}`;
    let cached = false;
    let orderCount = 0;

    try {
        // Layer 1: Check Redis cache
        const cachedVal = await redisClient.get(cacheKey);
        if (cachedVal) {
            cached = true;
        } else {
            // Cache miss — store for 60 seconds
            await redisClient.setEx(cacheKey, 60, JSON.stringify(stock));
        }
    } catch (err) {
        console.error('Redis error:', err.message);
    }

    try {
        // Layer 2: Enrich with PostgreSQL order count
        const result = await pgPool.query(
            'SELECT COUNT(*) as cnt FROM orders WHERE product LIKE $1',
            [`%${sku}%`]
        );
        orderCount = parseInt(result.rows[0].cnt, 10);
    } catch (err) {
        console.error('PostgreSQL error:', err.message);
    }

    res.json({
        sku: stock.sku,
        name: stock.name,
        quantity: stock.quantity,
        warehouse: stock.warehouse,
        cached,
        total_orders: orderCount,
    });
});

app.post('/api/stock/:sku/reserve', async (req, res) => {
    const sku = req.params.sku.toUpperCase();
    const stock = stockData[sku];
    if (!stock) {
        return res.status(404).json({ error: 'stock not found', sku });
    }

    const qty = parseInt(req.body.qty || '1', 10);
    if (stock.quantity < qty) {
        return res.status(409).json({ error: 'insufficient stock', available: stock.quantity, requested: qty });
    }

    stock.quantity -= qty;

    try {
        // Update Redis cache
        const cacheKey = `stock:${sku}`;
        await redisClient.decrBy(cacheKey, qty);
    } catch (err) {
        console.error('Redis decrBy error:', err.message);
    }

    res.json({ sku, reserved: qty, remaining: stock.quantity });
});

async function start() {
    try {
        await redisClient.connect();
        console.log('Connected to Redis');
    } catch (err) {
        console.error('Redis connect failed (will retry on requests):', err.message);
    }

    app.listen(PORT, '0.0.0.0', () => {
        console.log(`stock-service started on port ${PORT}`);
    });
}

start();
