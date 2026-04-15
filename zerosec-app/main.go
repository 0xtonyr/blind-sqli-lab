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

// Função para inicializar a conexão com o banco de dados
func initDB() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Erro ao carregar o arquivo .env")
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
		log.Fatal("Erro ao abrir conexão com o banco de dados:", errOpen)
	}

	if err := db.Ping(); err != nil {
		log.Fatal("Erro ao conectar no banco de dados:", err)
	}

	log.Println("Conectado ao banco de dados com sucesso!")
}

func submitHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password")

		// Verificar se o nome de usuário já existe (vulnerável a SQL Injection)
		var usernameExists bool
		query := "SELECT 1 FROM users WHERE username='" + username
		err := db.QueryRow(query).Scan(&usernameExists)
		if err != nil {
			http.Error(w, "Erro ao verificar nome de usuario", http.StatusInternalServerError)
			return
		}

		// Verificar se o e-mail já existe (usando consulta preparada)
		var emailExists bool
		stmt, err := db.Prepare("SELECT EXISTS(SELECT 1 FROM users WHERE email = ?)")
		if err != nil {
			http.Error(w, "Erro ao preparar consulta de e-mail", http.StatusInternalServerError)
			return
		}
		err = stmt.QueryRow(email).Scan(&emailExists)
		if err != nil {
			http.Error(w, "Erro ao verificar e-mail", http.StatusInternalServerError)
			return
		}

		// Retornar a resposta desejada no formato esperado pelo HTMX
		if usernameExists {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "Nome de usuário já em uso")
			return
		}

		if emailExists {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "E-mail já cadastrado")
			return
		}

		// Inserir os dados no banco de dados (vulnerável a SQL Injection)
		_, err = db.Exec(fmt.Sprintf("INSERT INTO users (username, email, password) VALUES ('%s', '%s', '%s')", username, email, password))
		if err != nil {
			http.Error(w, "Erro ao inserir no banco de dados", http.StatusInternalServerError)
			return
		}

		// Retornar a resposta de sucesso no formato esperado pelo HTMX
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Cadastro realizado com sucesso para o usuario: %s", username)
	} else {
		http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
	}
}

type JsonResponse struct {
	Message string `json:"message"`
}

func main() {
	// Inicializa o banco de dados
	initDB()
	defer db.Close() // Garante que o banco de dados será fechado ao final da execução

	// Rota para a página inicial
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "home.html")
	})

	// Rota para a página de cadastro
	http.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "register.html")
	})

	// Rota para o submit do cadastro
	http.HandleFunc("/submit", submitHandler)

	// Rota para verificar nome de usuário
	http.HandleFunc("/check-username", func(w http.ResponseWriter, r *http.Request) {
		username := r.URL.Query().Get("username")
		var exists int // Usando int para retornar 1 ou 0 (em vez de bool)

		// Construção da query vulnerável
		query := "SELECT EXISTS(SELECT 1 FROM users WHERE username='" + username + "');"
		log.Printf("Query executada: %s\n", query) // Log para demonstrar a consulta gerada

		// Executa a query diretamente (vulnerável a SQL Injection)
		err := db.QueryRow(query).Scan(&exists)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			response := JsonResponse{Message: "Erro ao verificar nome de usuario"}
			json.NewEncoder(w).Encode(response)
			return
		}

		// Retorna a resposta JSON
		w.Header().Set("Content-Type", "application/json")
		var response JsonResponse
		if exists == 1 {
			response = JsonResponse{Message: "usuario indisponivel"}
		} else {
			response = JsonResponse{Message: "usuario disponivel"}
		}
		json.NewEncoder(w).Encode(response)
	})

	// Rota para verificar a existência do e-mail
	http.HandleFunc("/check-email", func(w http.ResponseWriter, r *http.Request) {
		email := r.URL.Query().Get("email")
		var exists bool

		stmt, err := db.Prepare("SELECT EXISTS(SELECT 1 FROM users WHERE email = ?)")
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			response := JsonResponse{Message: "Erro ao preparar consulta de e-mail"}
			json.NewEncoder(w).Encode(response)
			return
		}
		err = stmt.QueryRow(email).Scan(&exists)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			response := JsonResponse{Message: "Erro ao verificar e-mail"}
			json.NewEncoder(w).Encode(response)
			return
		}

		// Retorna a resposta JSON
		w.Header().Set("Content-Type", "application/json")
		var response JsonResponse
		if exists {
			response = JsonResponse{Message: "email em uso"}
		} else {
			response = JsonResponse{Message: "email disponivel"}
		}
		json.NewEncoder(w).Encode(response)
	})

	// Servindo arquivos estáticos (CSS e imagem de fundo)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Inicia o servidor
	log.Println("Servidor iniciado na porta: 8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}
