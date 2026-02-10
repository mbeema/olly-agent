package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

var db *sql.DB

func main() {
	connStr := fmt.Sprintf(
		"host=%s port=%s dbname=%s user=%s password=%s sslmode=disable",
		getenv("DB_HOST", "localhost"),
		getenv("DB_PORT", "5432"),
		getenv("DB_NAME", "demo"),
		getenv("DB_USER", "demo"),
		getenv("DB_PASSWORD", "demo123"),
	)

	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Connection pool settings
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)

	if err := db.Ping(); err != nil {
		log.Fatal("cannot connect to database: ", err)
	}
	log.Println("connected to PostgreSQL")

	http.HandleFunc("/api/health", healthHandler)
	http.HandleFunc("/api/orders", ordersHandler)
	http.HandleFunc("/api/orders/", orderByIDHandler)

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
	rows, err := db.Query(
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
	err := db.QueryRow(
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
	err = db.QueryRow(
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
