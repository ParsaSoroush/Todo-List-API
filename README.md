## Todo List API

This project is a Go implementation of the [`todo-list-api` challenge on roadmap.sh](https://roadmap.sh/projects/todo-list-api). It exposes a REST API that lets users register, authenticate via JWT, and manage personal todo items stored in a MySQL database.

- Written in vanilla Go (`net/http`) for zero-framework clarity
- MySQL schema created automatically at startup
- BCrypt password hashing, JWT-based auth, and request-level validation
- Pagination-ready todo listing with `page` and `limit` query params

---

### Requirements

- Go 1.25+
- Running MySQL instance accessible from the API container/host
- Optional: `make`, `curl`, or another HTTP client for testing

> The default DSN inside `main.go` expects a database called `todo_list`, a user named `task-database`, and password `Task_Password$1234` on `localhost:3306`. Update `dsn` in `init()` or provide your own via environment variables before deploying to production.

---

### Getting Started

0. **Clone the repository**
   ```bash
   git clone https://github.com/ParsaSoroush/Todo-List-API.git
   cd Todo-List-API
   ```

1. **Install dependencies**
   ```bash
   go mod download
   ```

2. **Create the database**
   ```sql
   CREATE DATABASE todo_list;
   CREATE USER 'task-database'@'%' IDENTIFIED BY 'Task_Password$1234';
   GRANT ALL PRIVILEGES ON todo_list.* TO 'task-database'@'%';
   FLUSH PRIVILEGES;
   ```

3. **Run the API**
   ```bash
   go run main.go
   ```
   - Server defaults to `http://localhost:8081`
   - Override port with `PORT=:3000`

---

### Auth Flow

1. `POST /register` → create user + receive JWT
2. `POST /login` → exchange credentials for JWT
3. Use `Authorization: Bearer <token>` for every `/todos` request

Passwords are hashed with BCrypt before storage, and tokens expire after 24 hours.

---