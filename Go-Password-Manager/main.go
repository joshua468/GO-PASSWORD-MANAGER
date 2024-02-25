package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

const (
	sessionName = "session"
	sessionKey  = "secret-key"
	dbUser      = "joshua468"
	dbPassword  = "Temitope2080"
	dbName      = "mydb"
	dbHost      = "localhost"
	dbPort      = "3306"
	driverName  = "mysql"
)

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"-"`
}

type Password struct {
	ID       int    `json:"id"`
	UserID   int    `json:"-"`
	Service  string `json:"service"`
	Username string `json:"username"`
	Password string `json:"-"`
}
type DB struct {
	*sql.DB
}

var (
	store *sessions.CookieStore
	db    *DB
)

func init() {
	store = sessions.NewCookieStore([]byte(sessionKey))
	db = initDB()
}

func initDB() *DB {
	db, err := sql.Open("mysql", "joshua468"+":"+"Temitope2080"+"@tcp("+"localhost"+":"+"3306"+")/"+"mydb")
	if err != nil {
		log.Fatalf("Error connecting to database: %v", err)
	}
	if err := db.Ping(); err != nil {
		log.Fatalf("Error pinging database: %v", err)
	}
	return &DB{db}
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/signup", signupHandler).Methods("POST")
	r.HandleFunc("/login", loginHandler).Methods("POST")
	r.HandleFunc("/logout", logoutHandler).Methods("POST")
	r.HandleFunc("/passwords", requireLogin(getPasswordHandler)).Methods("GET")
	r.HandleFunc("/passwords", requireLogin(addPasswordHandler)).Methods("POST")

	http.Handle("/", r)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
func signupHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Could not hash password", http.StatusInternalServerError)
		return
	}
	user.Password = string(hashedPassword)

	_, err = db.Exec("INSERT INTO users(username,password) VALUES(?,?)", user.Username, user.Password)
	if err != nil {
		http.Error(w, "Error creating user", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusCreated)
}
func loginHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var storedUser User
	err := db.QueryRow("SELECT * FROM users WHERE username =?", user.Username).Scan(&storedUser.ID, &storedUser.Username, &storedUser.Password)
	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(storedUser.Password), []byte(user.Password)); err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}
	session, _ := store.Get(r, sessionName)
	session.Values["user"] = storedUser.Username
	session.Save(r, w)
	w.WriteHeader(http.StatusOK)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, sessionName)
	delete(session.Values, "user")
	session.Save(r, w)
}

func requireLogin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, sessionName)
		if _, ok := session.Values["user"]; !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	}
}

func getPasswordHandler(w http.ResponseWriter, r *http.Request) {
	user := getCurrentUser(r)
	rows, err := db.Query("SELECT * FROM passwords WHERE user_id =?", user.ID)
	if err != nil {
		http.Error(w, "Error fetching passwords", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	passwords := make([]Password, 0)
	for rows.Next() {
		var password Password
		if err := rows.Scan(&password.ID, &password.UserID, &password.Service, &password.Username, &password.Password); err != nil {
			http.Error(w, "Error scanning passwords", http.StatusInternalServerError)
			return
		}
		passwords = append(passwords, password)
	}
	json.NewEncoder(w).Encode(passwords)
}

func addPasswordHandler(w http.ResponseWriter, r *http.Request) {
	var password Password
	if err := json.NewDecoder(r.Body).Decode(&password); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	user := getCurrentUser(r)
	_, err := db.Exec("INSERT INTO passwords(user_id,service,username,password) VALUES(?,?,?,?)", user.ID, password.Service, password.Username, password.Password)
	if err != nil {
		http.Error(w, "Error adding password", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func getCurrentUser(r *http.Request) User {
	session, _ := store.Get(r, sessionName)
	username := session.Values["user"].(string)

	var user User
	err := db.QueryRow("SELECT * FROM users WHERE username = ?", username).Scan(&user.ID, &user.Username, &user.Password)
	if err != nil {
		log.Fatal(err)
	}
	return user
}
