package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

const (
	jwtSecret   = "your-super-secret-key-change-this-in-production"
	defaultPort = ":8081"
)

var db *sql.DB

// Models
type User struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"-"`
}

type Todo struct {
	ID          int       `json:"id"`
	UserID      int       `json:"-"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type AuthRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RegisterRequest struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type TodoRequest struct {
	Title       string `json:"title"`
	Description string `json:"description"`
}

type TokenResponse struct {
	Token string `json:"token"`
}

type TodosResponse struct {
	Data  []Todo `json:"data"`
	Page  int    `json:"page"`
	Limit int    `json:"limit"`
	Total int    `json:"total"`
}

type ErrorResponse struct {
	Message string `json:"message"`
}

// JWT Claims
type Claims struct {
	UserID int    `json:"user_id"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

func init() {
	dsn := fmt.Sprintf("task-database:Task_Password$1234@tcp(localhost:3306)/todo_list?parseTime=true")
	var err error
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	if err = db.Ping(); err != nil {
		log.Fatal("Failed to ping database:", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	createTables()
	log.Println("Database connected successfully")
}

func createTables() {
	usersTable := `
	CREATE TABLE IF NOT EXISTS users (
		id INT AUTO_INCREMENT PRIMARY KEY,
		name VARCHAR(255) NOT NULL,
		email VARCHAR(255) UNIQUE NOT NULL,
		password VARCHAR(255) NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`

	todosTable := `
	CREATE TABLE IF NOT EXISTS todos (
		id INT AUTO_INCREMENT PRIMARY KEY,
		user_id INT NOT NULL,
		title VARCHAR(255) NOT NULL,
		description LONGTEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
		INDEX idx_todos_user_id (user_id)
	);`

	if _, err := db.Exec(usersTable); err != nil {
		log.Fatal("Failed to create users table:", err)
	}

	if _, err := db.Exec(todosTable); err != nil {
		log.Fatal("Failed to create todos table:", err)
	}
}

// Helper functions
func respondJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(payload)
}

func respondError(w http.ResponseWriter, status int, message string) {
	respondJSON(w, status, ErrorResponse{Message: message})
}

func generateToken(userID int, email string) (string, error) {
	claims := &Claims{
		UserID: userID,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(jwtSecret))
}

func validateEmail(email string) bool {
	re := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return re.MatchString(email)
}

func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}

func comparePasswords(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

func getUserIDFromContext(r *http.Request) int {
	userID, _ := strconv.Atoi(r.Header.Get("X-User-ID"))
	return userID
}

// Handlers
func register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Name == "" || req.Email == "" || req.Password == "" {
		respondError(w, http.StatusBadRequest, "Name, email, and password are required")
		return
	}

	if !validateEmail(req.Email) {
		respondError(w, http.StatusBadRequest, "Invalid email format")
		return
	}

	if len(req.Password) < 6 {
		respondError(w, http.StatusBadRequest, "Password must be at least 6 characters")
		return
	}

	hashedPassword, err := hashPassword(req.Password)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to process password")
		return
	}

	res, err := db.Exec("INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
		req.Name, req.Email, hashedPassword,
	)

	if err != nil {
		if strings.Contains(err.Error(), "Duplicate entry") {
			respondError(w, http.StatusConflict, "Email already registered")
			return
		}
		respondError(w, http.StatusInternalServerError, "Failed to create user")
		return
	}

	userID64, _ := res.LastInsertId()
	userID := int(userID64)

	token, err := generateToken(userID, req.Email)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to generate token")
		return
	}

	respondJSON(w, http.StatusCreated, TokenResponse{Token: token})
}

func login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Email == "" || req.Password == "" {
		respondError(w, http.StatusBadRequest, "Email and password are required")
		return
	}

	var user User
	err := db.QueryRow("SELECT id, email, password FROM users WHERE email = ?", req.Email).
		Scan(&user.ID, &user.Email, &user.Password)

	if err == sql.ErrNoRows {
		respondError(w, http.StatusUnauthorized, "Invalid email or password")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Database error")
		return
	}

	if err = comparePasswords(user.Password, req.Password); err != nil {
		respondError(w, http.StatusUnauthorized, "Invalid email or password")
		return
	}

	token, err := generateToken(user.ID, user.Email)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to generate token")
		return
	}

	respondJSON(w, http.StatusOK, TokenResponse{Token: token})
}

func createTodo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	userID := getUserIDFromContext(r)

	var req TodoRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Title == "" {
		respondError(w, http.StatusBadRequest, "Title is required")
		return
	}

	if len(req.Title) > 255 {
		respondError(w, http.StatusBadRequest, "Title must be less than 255 characters")
		return
	}

	now := time.Now()

	res, err := db.Exec(
		"INSERT INTO todos (user_id, title, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
		userID, req.Title, req.Description, now, now,
	)

	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to create todo")
		return
	}

	id64, _ := res.LastInsertId()
	id := int(id64)

	todo := Todo{
		ID:          id,
		Title:       req.Title,
		Description: req.Description,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	respondJSON(w, http.StatusCreated, todo)
}

func updateTodo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	userID := getUserIDFromContext(r)
	todoID := extractIDFromPath(r.URL.Path, "/todos/")

	if todoID == 0 {
		respondError(w, http.StatusBadRequest, "Invalid todo ID")
		return
	}

	var req TodoRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Title == "" {
		respondError(w, http.StatusBadRequest, "Title is required")
		return
	}

	var dbUserID int
	err := db.QueryRow("SELECT user_id FROM todos WHERE id = ?", todoID).Scan(&dbUserID)
	if err == sql.ErrNoRows {
		respondError(w, http.StatusNotFound, "Todo not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Database error")
		return
	}

	if dbUserID != userID {
		respondError(w, http.StatusForbidden, "Forbidden")
		return
	}

	now := time.Now()

	_, err = db.Exec(
		"UPDATE todos SET title = ?, description = ?, updated_at = ? WHERE id = ?",
		req.Title, req.Description, now, todoID,
	)

	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to update todo")
		return
	}

	todo := Todo{
		ID:          todoID,
		Title:       req.Title,
		Description: req.Description,
		UpdatedAt:   now,
	}

	respondJSON(w, http.StatusOK, todo)
}

func deleteTodo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	userID := getUserIDFromContext(r)
	todoID := extractIDFromPath(r.URL.Path, "/todos/")

	if todoID == 0 {
		respondError(w, http.StatusBadRequest, "Invalid todo ID")
		return
	}

	var dbUserID int
	err := db.QueryRow("SELECT user_id FROM todos WHERE id = ?", todoID).Scan(&dbUserID)
	if err == sql.ErrNoRows {
		respondError(w, http.StatusNotFound, "Todo not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Database error")
		return
	}

	if dbUserID != userID {
		respondError(w, http.StatusForbidden, "Forbidden")
		return
	}

	_, err = db.Exec("DELETE FROM todos WHERE id = ?", todoID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to delete todo")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func getTodos(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	userID := getUserIDFromContext(r)
	page := 1
	limit := 10

	if p := r.URL.Query().Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}

	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}

	offset := (page - 1) * limit

	var total int
	err := db.QueryRow("SELECT COUNT(*) FROM todos WHERE user_id = ?", userID).Scan(&total)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Database error")
		return
	}

	rows, err := db.Query(
		"SELECT id, title, description, created_at, updated_at FROM todos WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
		userID, limit, offset,
	)

	if err != nil {
		respondError(w, http.StatusInternalServerError, "Database error")
		return
	}
	defer rows.Close()

	todos := []Todo{}
	for rows.Next() {
		var todo Todo
		if err := rows.Scan(&todo.ID, &todo.Title, &todo.Description, &todo.CreatedAt, &todo.UpdatedAt); err != nil {
			respondError(w, http.StatusInternalServerError, "Database error")
			return
		}
		todos = append(todos, todo)
	}

	if todos == nil {
		todos = []Todo{}
	}

	response := TodosResponse{
		Data:  todos,
		Page:  page,
		Limit: limit,
		Total: total,
	}

	respondJSON(w, http.StatusOK, response)
}

// Router utils
func extractIDFromPath(path, prefix string) int {
	parts := strings.Split(path, prefix)
	if len(parts) < 2 {
		return 0
	}
	id, _ := strconv.Atoi(parts[1])
	return id
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			respondError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		claims := &Claims{}

		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(jwtSecret), nil
		})

		if err != nil || !token.Valid {
			respondError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}

		r.Header.Set("X-User-ID", strconv.Itoa(claims.UserID))
		next(w, r)
	}
}

// Router
func router(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	switch {
	case path == "/register":
		register(w, r)
	case path == "/login":
		login(w, r)
	case path == "/todos" && r.Method == http.MethodPost:
		authMiddleware(createTodo)(w, r)
	case path == "/todos" && r.Method == http.MethodGet:
		authMiddleware(getTodos)(w, r)
	case strings.HasPrefix(path, "/todos/") && r.Method == http.MethodPut:
		authMiddleware(updateTodo)(w, r)
	case strings.HasPrefix(path, "/todos/") && r.Method == http.MethodDelete:
		authMiddleware(deleteTodo)(w, r)
	default:
		respondError(w, http.StatusNotFound, "Not found")
	}
}

func main() {
	defer db.Close()

	http.HandleFunc("/", router)

	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}

	log.Printf("Server starting on http://localhost%s\n", port)
	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatal(err)
	}
}
