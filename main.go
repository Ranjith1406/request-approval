package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
)

var db *sql.DB

/* ===================== MODELS ===================== */

type User struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"` // associate | lead | manager
}

type Request struct {
	ID         int    `json:"id"`
	EmployeeID int    `json:"employee_id"`
	Content    string `json:"content"` // Leave type: Casual / Earned / CompOff
	Status     string `json:"status"`
	LeadID     *int   `json:"lead_id"`
	ManagerID  *int   `json:"manager_id"`
	Comment    string `json:"comment"` // Employee / rejection comment
}

/* ===================== CORS ===================== */

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Content-Type", "application/json")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

/* ===================== MAIN ===================== */

func main() {
	var err error

	db, err = sql.Open(
		"postgres",
		"host=localhost port=5432 user=postgres password=postgres dbname=approval_system sslmode=disable",
	)
	if err != nil {
		log.Fatal(err)
	}

	createTables()

	r := mux.NewRouter()

	// Auth
	r.HandleFunc("/signup", signup).Methods("POST")
	r.HandleFunc("/login", login).Methods("POST")

	// Requests
	r.HandleFunc("/request", createRequest).Methods("POST")
	r.HandleFunc("/requests", getRequests).Methods("GET")

	// Lead actions
	r.HandleFunc("/lead-action/{id}", leadAction).Methods("PUT")

	// Manager actions
	r.HandleFunc("/manager-approve/{id}", managerApprove).Methods("PUT")

	// Reject
	r.HandleFunc("/reject/{id}", rejectRequest).Methods("PUT")

	// Dropdown data
	r.HandleFunc("/team-leads", getTeamLeads).Methods("GET")
	r.HandleFunc("/managers", getManagers).Methods("GET")

	log.Println("🚀 Server running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", corsMiddleware(r)))
}

/* ===================== TABLE CREATION ===================== */

func createTables() {
	db.Exec(`
	CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		name TEXT,
		email TEXT UNIQUE,
		password TEXT,
		role TEXT
	)`)

	db.Exec(`
	CREATE TABLE IF NOT EXISTS requests (
		id SERIAL PRIMARY KEY,
		employee_id INT REFERENCES users(id),
		content TEXT,
		status TEXT,
		lead_id INT REFERENCES users(id),
		manager_id INT REFERENCES users(id),
		comment TEXT
	)`)
}

/* ===================== AUTH ===================== */

func signup(w http.ResponseWriter, r *http.Request) {
	var u User
	json.NewDecoder(r.Body).Decode(&u)

	_, err := db.Exec(
		"INSERT INTO users (name, email, password, role) VALUES ($1,$2,$3,$4)",
		u.Name, u.Email, u.Password, u.Role,
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"message": "Signup successful",
	})
}

func login(w http.ResponseWriter, r *http.Request) {
	var u User
	json.NewDecoder(r.Body).Decode(&u)

	var dbUser User
	err := db.QueryRow(
		"SELECT id, email, role, name FROM users WHERE email=$1 AND password=$2",
		u.Email, u.Password,
	).Scan(&dbUser.ID, &dbUser.Email, &dbUser.Role, &dbUser.Name)

	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	json.NewEncoder(w).Encode(dbUser)
}

/* ===================== REQUEST FLOW ===================== */

func createRequest(w http.ResponseWriter, r *http.Request) {
	var req Request
	json.NewDecoder(r.Body).Decode(&req)

	// ✅ Validation (prevents empty submission)
	if req.EmployeeID == 0 || req.Content == "" || req.LeadID == nil {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	_, err := db.Exec(
		`INSERT INTO requests (employee_id, content, status, lead_id, comment)
		 VALUES ($1,$2,'pending_lead',$3,$4)`,
		req.EmployeeID,
		req.Content,
		req.LeadID,
		req.Comment,
	)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"message": "Leave request submitted successfully",
	})
}

func getRequests(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(
		"SELECT id, employee_id, content, status, lead_id, manager_id, comment FROM requests",
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var list []Request

	for rows.Next() {
		var req Request
		var manager sql.NullInt32 // handle nullable manager_id

		err := rows.Scan(
			&req.ID,
			&req.EmployeeID,
			&req.Content,
			&req.Status,
			&req.LeadID,
			&manager,
			&req.Comment,
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if manager.Valid {
			req.ManagerID = new(int)
			*req.ManagerID = int(manager.Int32)
		} else {
			req.ManagerID = nil
		}

		list = append(list, req)
	}

	json.NewEncoder(w).Encode(list)
}

/* ===================== LEAD ACTION ===================== */

func leadAction(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(mux.Vars(r)["id"])
	action := r.URL.Query().Get("action") // approve | reject | forward

	switch action {

	case "approve":
		db.Exec("UPDATE requests SET status='approved' WHERE id=$1", id)

	case "reject":
		var payload struct{ Comment string }
		json.NewDecoder(r.Body).Decode(&payload)
		db.Exec(
			"UPDATE requests SET status='rejected', comment=$1 WHERE id=$2",
			payload.Comment, id,
		)

	case "forward":
		var payload struct{ ManagerID int }
		json.NewDecoder(r.Body).Decode(&payload)
		db.Exec(
			"UPDATE requests SET status='pending_manager', manager_id=$1 WHERE id=$2",
			payload.ManagerID, id,
		)
	}

	json.NewEncoder(w).Encode(map[string]string{
		"message": "Action completed",
	})
}

/* ===================== MANAGER ACTION ===================== */

func managerApprove(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(mux.Vars(r)["id"])
	db.Exec("UPDATE requests SET status='approved' WHERE id=$1", id)

	json.NewEncoder(w).Encode(map[string]string{
		"message": "Manager approved",
	})
}

/* ===================== REJECT ===================== */

func rejectRequest(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(mux.Vars(r)["id"])
	var payload struct{ Comment string }
	json.NewDecoder(r.Body).Decode(&payload)

	db.Exec(
		"UPDATE requests SET status='rejected', comment=$1 WHERE id=$2",
		payload.Comment, id,
	)

	json.NewEncoder(w).Encode(map[string]string{
		"message": "Rejected",
	})
}

/* ===================== DROPDOWNS ===================== */

// Get all team leads
func getTeamLeads(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT id, name FROM users WHERE role='lead'")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var leads []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Name); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		leads = append(leads, u)
	}

	json.NewEncoder(w).Encode(leads)
}

// Get all managers
func getManagers(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT id, name FROM users WHERE role='manager'")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var managers []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Name); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		managers = append(managers, u)
	}

	json.NewEncoder(w).Encode(managers)
}
