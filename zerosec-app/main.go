package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	_ "github.com/go-sql-driver/mysql"
	"github.com/joho/godotenv"
)

var db *sql.DB

// initDB initializes the database connection.
func initDB() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	dbUser := os.Getenv("MYSQL_USER")
	dbPassword := os.Getenv("MYSQL_PASSWORD")
	dbHost := os.Getenv("MYSQL_HOST")
	dbPort := os.Getenv("MYSQL_PORT")
	dbName := os.Getenv("MYSQL_DB")

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", dbUser, dbPassword, dbHost, dbPort, dbName)

	var errOpen error
	db, errOpen = sql.Open("mysql", dsn)
	if errOpen != nil {
		log.Fatal("Error opening database connection:", errOpen)
	}

	if err := db.Ping(); err != nil {
		log.Fatal("Error connecting to the database:", err)
	}

	log.Println("Connected to the database successfully!")
}

func submitHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password")

		// Check whether the username already exists (vulnerable to SQL Injection)
		var usernameExists bool
		query := "SELECT 1 FROM users WHERE username='" + username
		err := db.QueryRow(query).Scan(&usernameExists)
		if err != nil {
			http.Error(w, "Error checking username", http.StatusInternalServerError)
			return
		}

		// Check whether the email already exists (using a prepared statement)
		var emailExists bool
		stmt, err := db.Prepare("SELECT EXISTS(SELECT 1 FROM users WHERE email = ?)")
		if err != nil {
			http.Error(w, "Error preparing email query", http.StatusInternalServerError)
			return
		}
		err = stmt.QueryRow(email).Scan(&emailExists)
		if err != nil {
			http.Error(w, "Error checking email", http.StatusInternalServerError)
			return
		}

		// Return the response in the format expected by HTMX
		if usernameExists {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "Username already in use")
			return
		}

		if emailExists {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "Email already registered")
			return
		}

		// Insert the data into the database (vulnerable to SQL Injection)
		_, err = db.Exec(fmt.Sprintf("INSERT INTO users (username, email, password) VALUES ('%s', '%s', '%s')", username, email, password))
		if err != nil {
			http.Error(w, "Error inserting into the database", http.StatusInternalServerError)
			return
		}

		// Return the success response in the format expected by HTMX
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Registration successful for user: %s", username)
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

type JsonResponse struct {
	Message string `json:"message"`
}

func main() {
	// Initialize the database
	initDB()
	defer db.Close() // Ensure the database is closed when execution ends

	// Home page route
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "home.html")
	})

	// Registration page route
	http.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "register.html")
	})

	// Registration submit route
	http.HandleFunc("/submit", submitHandler)

	// Username availability check route
	http.HandleFunc("/check-username", func(w http.ResponseWriter, r *http.Request) {
		username := r.URL.Query().Get("username")
		var exists int // Using int to return 1 or 0 (instead of bool)

		// Vulnerable query construction
		query := "SELECT EXISTS(SELECT 1 FROM users WHERE username='" + username + "');"
		log.Printf("Executed query: %s\n", query) // Log to demonstrate the generated query

		// Execute the query directly (vulnerable to SQL Injection)
		err := db.QueryRow(query).Scan(&exists)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			response := JsonResponse{Message: "Error checking username"}
			json.NewEncoder(w).Encode(response)
			return
		}

		// Return the JSON response
		w.Header().Set("Content-Type", "application/json")
		var response JsonResponse
		if exists == 1 {
			response = JsonResponse{Message: "username unavailable"}
		} else {
			response = JsonResponse{Message: "username available"}
		}
		json.NewEncoder(w).Encode(response)
	})

	// Email existence check route
	http.HandleFunc("/check-email", func(w http.ResponseWriter, r *http.Request) {
		email := r.URL.Query().Get("email")
		var exists bool

		stmt, err := db.Prepare("SELECT EXISTS(SELECT 1 FROM users WHERE email = ?)")
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			response := JsonResponse{Message: "Error preparing email query"}
			json.NewEncoder(w).Encode(response)
			return
		}
		err = stmt.QueryRow(email).Scan(&exists)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			response := JsonResponse{Message: "Error checking email"}
			json.NewEncoder(w).Encode(response)
			return
		}

		// Return the JSON response
		w.Header().Set("Content-Type", "application/json")
		var response JsonResponse
		if exists {
			response = JsonResponse{Message: "email in use"}
		} else {
			response = JsonResponse{Message: "email available"}
		}
		json.NewEncoder(w).Encode(response)
	})

	// Serve static files (CSS and background image)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Start the server
	log.Println("Server started on port: 8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}
