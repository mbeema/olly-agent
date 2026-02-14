package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
)

var catalogServiceURL string

var (
	pgDB    *sql.DB // PostgreSQL — orders
	mysqlDB *sql.DB // MySQL — inventory
)

func main() {
	// PostgreSQL connection (orders)
	pgConnStr := fmt.Sprintf(
		"host=%s port=%s dbname=%s user=%s password=%s sslmode=disable",
		getenv("DB_HOST", "localhost"),
		getenv("DB_PORT", "5432"),
		getenv("DB_NAME", "demo"),
		getenv("DB_USER", "demo"),
		getenv("DB_PASSWORD", "demo123"),
	)

	var err error
	pgDB, err = sql.Open("postgres", pgConnStr)
	if err != nil {
		log.Fatal(err)
	}
	defer pgDB.Close()
	pgDB.SetMaxOpenConns(10)
	pgDB.SetMaxIdleConns(5)

	if err := pgDB.Ping(); err != nil {
		log.Fatal("cannot connect to PostgreSQL: ", err)
	}
	log.Println("connected to PostgreSQL")

	// MySQL connection (inventory)
	mysqlConnStr := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true",
		getenv("MYSQL_USER", "demo"),
		getenv("MYSQL_PASSWORD", "demo123"),
		getenv("MYSQL_HOST", "localhost"),
		getenv("MYSQL_PORT", "3306"),
		getenv("MYSQL_DB", "inventory"),
	)

	mysqlDB, err = sql.Open("mysql", mysqlConnStr)
	if err != nil {
		log.Printf("WARNING: MySQL not available: %v", err)
	} else {
		mysqlDB.SetMaxOpenConns(10)
		mysqlDB.SetMaxIdleConns(5)
		if err := mysqlDB.Ping(); err != nil {
			log.Printf("WARNING: MySQL not reachable: %v", err)
			mysqlDB = nil
		} else {
			log.Println("connected to MySQL (inventory)")
		}
	}

	catalogServiceURL = getenv("CATALOG_SERVICE_URL", "http://localhost:8081")

	http.HandleFunc("/api/health", healthHandler)
	http.HandleFunc("/api/orders", ordersHandler)
	http.HandleFunc("/api/orders/", orderByIDHandler)
	http.HandleFunc("/api/inventory", inventoryHandler)
	http.HandleFunc("/api/inventory/", inventoryBySkuHandler)
	http.HandleFunc("/api/checkout", checkoutHandler)
	http.HandleFunc("/api/fullchain", fullchainHandler)

	port := getenv("PORT", "3001")
	log.Printf("order-service listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"service": "order-service",
	})
}

func ordersHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		listOrders(w, r)
	case "POST":
		createOrder(w, r)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func listOrders(w http.ResponseWriter, r *http.Request) {
	rows, err := pgDB.Query(
		"SELECT id, user_id, product, amount, created_at FROM orders ORDER BY id DESC LIMIT 50",
	)
	if err != nil {
		log.Printf("query error: %v", err)
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()

	var orders []map[string]interface{}
	for rows.Next() {
		var id, userID int
		var product string
		var amount float64
		var createdAt time.Time
		if err := rows.Scan(&id, &userID, &product, &amount, &createdAt); err != nil {
			continue
		}
		orders = append(orders, map[string]interface{}{
			"id":         id,
			"user_id":    userID,
			"product":    product,
			"amount":     amount,
			"created_at": createdAt.Format(time.RFC3339),
		})
	}
	if orders == nil {
		orders = []map[string]interface{}{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(orders)
}

func createOrder(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID  int     `json:"user_id"`
		Product string  `json:"product"`
		Amount  float64 `json:"amount"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", 400)
		return
	}

	var id int
	err := pgDB.QueryRow(
		"INSERT INTO orders (user_id, product, amount) VALUES ($1, $2, $3) RETURNING id",
		req.UserID, req.Product, req.Amount,
	).Scan(&id)
	if err != nil {
		log.Printf("insert error: %v", err)
		http.Error(w, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(201)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":      id,
		"user_id": req.UserID,
		"product": req.Product,
		"amount":  req.Amount,
	})
}

func orderByIDHandler(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		http.Error(w, "bad request", 400)
		return
	}
	id, err := strconv.Atoi(parts[3])
	if err != nil {
		http.Error(w, "invalid id", 400)
		return
	}

	var userID int
	var product string
	var amount float64
	var createdAt time.Time
	err = pgDB.QueryRow(
		"SELECT user_id, product, amount, created_at FROM orders WHERE id = $1", id,
	).Scan(&userID, &product, &amount, &createdAt)
	if err == sql.ErrNoRows {
		http.Error(w, "not found", 404)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":         id,
		"user_id":    userID,
		"product":    product,
		"amount":     amount,
		"created_at": createdAt.Format(time.RFC3339),
	})
}

// --- Inventory endpoints (MySQL) ---

func inventoryHandler(w http.ResponseWriter, r *http.Request) {
	if mysqlDB == nil {
		http.Error(w, `{"error":"MySQL not available"}`, 503)
		return
	}

	switch r.Method {
	case "GET":
		listInventory(w, r)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func listInventory(w http.ResponseWriter, r *http.Request) {
	rows, err := mysqlDB.Query(
		"SELECT id, name, sku, price, stock, created_at FROM products ORDER BY id",
	)
	if err != nil {
		log.Printf("MySQL query error: %v", err)
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()

	var products []map[string]interface{}
	for rows.Next() {
		var id, stock int
		var name, sku string
		var price float64
		var createdAt time.Time
		if err := rows.Scan(&id, &name, &sku, &price, &stock, &createdAt); err != nil {
			continue
		}
		products = append(products, map[string]interface{}{
			"id":         id,
			"name":       name,
			"sku":        sku,
			"price":      price,
			"stock":      stock,
			"created_at": createdAt.Format(time.RFC3339),
		})
	}
	if products == nil {
		products = []map[string]interface{}{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(products)
}

func inventoryBySkuHandler(w http.ResponseWriter, r *http.Request) {
	if mysqlDB == nil {
		http.Error(w, `{"error":"MySQL not available"}`, 503)
		return
	}

	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		http.Error(w, "bad request", 400)
		return
	}
	sku := parts[3]

	var id, stock int
	var name string
	var price float64
	err := mysqlDB.QueryRow(
		"SELECT id, name, price, stock FROM products WHERE sku = ?", sku,
	).Scan(&id, &name, &price, &stock)
	if err == sql.ErrNoRows {
		http.Error(w, `{"error":"product not found"}`, 404)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":    id,
		"name":  name,
		"sku":   sku,
		"price": price,
		"stock": stock,
	})
}

// --- Checkout endpoint (MySQL inventory check + PostgreSQL order creation) ---

func checkoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", 405)
		return
	}
	if mysqlDB == nil {
		http.Error(w, `{"error":"MySQL not available"}`, 503)
		return
	}

	var req struct {
		UserID int    `json:"user_id"`
		SKU    string `json:"sku"`
		Qty    int    `json:"qty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", 400)
		return
	}
	if req.Qty <= 0 {
		req.Qty = 1
	}

	// Step 1: Check inventory in MySQL
	var productName string
	var price float64
	var stock int
	err := mysqlDB.QueryRow(
		"SELECT name, price, stock FROM products WHERE sku = ?", req.SKU,
	).Scan(&productName, &price, &stock)
	if err == sql.ErrNoRows {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(404)
		json.NewEncoder(w).Encode(map[string]string{"error": "product not found"})
		return
	}
	if err != nil {
		log.Printf("MySQL inventory check error: %v", err)
		http.Error(w, err.Error(), 500)
		return
	}

	if stock < req.Qty {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(409)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":     "insufficient stock",
			"available": stock,
			"requested": req.Qty,
		})
		return
	}

	// Step 2: Decrement stock in MySQL
	_, err = mysqlDB.Exec(
		"UPDATE products SET stock = stock - ? WHERE sku = ? AND stock >= ?",
		req.Qty, req.SKU, req.Qty,
	)
	if err != nil {
		log.Printf("MySQL stock update error: %v", err)
		http.Error(w, err.Error(), 500)
		return
	}

	// Step 3: Create order in PostgreSQL
	amount := price * float64(req.Qty)
	var orderID int
	err = pgDB.QueryRow(
		"INSERT INTO orders (user_id, product, amount) VALUES ($1, $2, $3) RETURNING id",
		req.UserID, productName, amount,
	).Scan(&orderID)
	if err != nil {
		log.Printf("PostgreSQL order insert error: %v", err)
		// Rollback stock (best effort)
		mysqlDB.Exec("UPDATE products SET stock = stock + ? WHERE sku = ?", req.Qty, req.SKU)
		http.Error(w, err.Error(), 500)
		return
	}

	log.Printf("checkout: order=%d user=%d product=%s qty=%d amount=%.2f",
		orderID, req.UserID, productName, req.Qty, amount)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(201)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"order_id": orderID,
		"user_id":  req.UserID,
		"product":  productName,
		"sku":      req.SKU,
		"qty":      req.Qty,
		"amount":   amount,
		"status":   "confirmed",
	})
}

// --- Full-chain endpoint: Go → Java → .NET → Node.js → Redis + PostgreSQL ---

func fullchainHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", 405)
		return
	}

	var req struct {
		UserID int    `json:"user_id"`
		SKU    string `json:"sku"`
		Qty    int    `json:"qty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", 400)
		return
	}
	if req.Qty <= 0 {
		req.Qty = 1
	}

	// Step 1: Check MySQL inventory
	var productName string
	var price float64
	var stock int
	if mysqlDB != nil {
		err := mysqlDB.QueryRow(
			"SELECT name, price, stock FROM products WHERE sku = ?", req.SKU,
		).Scan(&productName, &price, &stock)
		if err != nil {
			log.Printf("fullchain: MySQL inventory error: %v", err)
		}
	}

	// Step 2: Call Java catalog-service → .NET pricing → Node.js stock → Redis + PG
	catalogURL := fmt.Sprintf("%s/api/catalog/%s", catalogServiceURL, req.SKU)
	resp, err := http.Get(catalogURL)
	var catalog json.RawMessage
	if err != nil {
		log.Printf("fullchain: catalog-service error: %v", err)
		catalog = json.RawMessage(`{"error":"catalog-service unreachable"}`)
	} else {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		catalog = body
	}

	// Step 3: Create order in PostgreSQL
	amount := price * float64(req.Qty)
	var orderID int
	err = pgDB.QueryRow(
		"INSERT INTO orders (user_id, product, amount) VALUES ($1, $2, $3) RETURNING id",
		req.UserID, fmt.Sprintf("%s (fullchain)", productName), amount,
	).Scan(&orderID)
	if err != nil {
		log.Printf("fullchain: PostgreSQL order error: %v", err)
		http.Error(w, err.Error(), 500)
		return
	}

	log.Printf("fullchain: order=%d user=%d sku=%s amount=%.2f", orderID, req.UserID, req.SKU, amount)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(201)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"order_id":  orderID,
		"user_id":   req.UserID,
		"sku":       req.SKU,
		"qty":       req.Qty,
		"amount":    amount,
		"inventory": map[string]interface{}{"name": productName, "price": price, "stock": stock},
		"catalog":   catalog,
		"status":    "confirmed",
	})
}
