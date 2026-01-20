package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
    "time"
    "github.com/golang-jwt/jwt/v5"
	"strings"
	"context"
	"net/smtp"
	"os"
    "path/filepath"
	"fmt"
	"io"
)

var db *sql.DB

var jwtSecret = []byte("my_secret_key") //token

/* struct */


type User struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"` // associate | lead | manager
	Department string `json:"department"`
	Phone      string `json:"phone"`
	Address    string `json:"address"`
	PhotoURL   string `json:"photo_url"`
	TeamLeadID *int64  `json:"team_lead_id,omitempty"`
    ManagerID  *int64  `json:"manager_id,omitempty"`
}

type Request struct {
	ID         int    `json:"id"`
	EmployeeID int    `json:"employee_id"`
	Content    string `json:"content"` // Leave type: Casual / Earned / CompOff
	Status     string `json:"status"`
	LeadID     *int   `json:"lead_id"`
	ManagerID  *int   `json:"manager_id"`
	Comment    string `json:"comment"` // Employee request comment
	EmployeeName string `json:"employee_name"`
	RejectionComment sql.NullString `json:"rejection_comment"` 
}

/*cors */

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Content-Type", "application/json")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

/* main function */

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
	r.PathPrefix("/uploads/").Handler( http.StripPrefix("/uploads/", http.FileServer(http.Dir("./uploads"))),)

	// Auth
	r.HandleFunc("/signup", signup).Methods("POST")
	r.HandleFunc("/login", login).Methods("POST")

	// Requests
	r.HandleFunc("/request", createRequest).Methods("POST")
	r.HandleFunc("/requests", authMiddleware(getRequests)).Methods("GET")
    r.HandleFunc("/request/{id}/resubmit", updateRequest).Methods("PUT")

	// Lead actions
	r.HandleFunc("/lead-action/{id}", authMiddleware(leadAction)).Methods("PUT")

	// Manager actions
	//r.HandleFunc("/manager-approve/{id}", managerApprove).Methods("PUT")
	r.HandleFunc("/manager-action/{id}", authMiddleware(managerAction)).Methods("PUT")

	// Reject
	//r.HandleFunc("/reject/{id}", rejectRequest).Methods("PUT")

	// Dropdown data
	r.HandleFunc("/team-leads", getTeamLeads).Methods("GET")
	r.HandleFunc("/managers", getManagers).Methods("GET")

	//Edit Users
	//r.HandleFunc("/users", getUsers).Methods("GET")
	r.HandleFunc("/users", authMiddleware(getUsers, "admin")).Methods("GET")
    //r.HandleFunc("/users/{id}/role", updateUserRole).Methods("PUT")
    r.HandleFunc("/users/{id}", authMiddleware(deleteUser, "admin")).Methods("DELETE")
	//r.HandleFunc("/users/{id}", authMiddleware(updateProfile, "admin", "user")).Methods("PUT")
	r.HandleFunc("/users/{id}", authMiddleware(updateProfile)).Methods("PUT")

	r.HandleFunc("/me", authMiddleware(getMe)).Methods("GET")

	r.HandleFunc("/users/delete-with-requests/{id}",authMiddleware(deleteUserAndRequests, "admin")).Methods("DELETE")

	/*create user*/
	r.HandleFunc("/admin/create-user", authMiddleware(createUserByAdmin, "admin")).Methods("POST")

    r.HandleFunc("/profile/photo", authMiddleware(updateProfilePhoto)).Methods("PUT")
    r.HandleFunc("/profile/photo", authMiddleware(deleteProfilePhoto)).Methods("DELETE")

	r.HandleFunc("/change-password", authMiddleware(changePassword)).Methods("PUT")


	log.Println("🚀 Server running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", corsMiddleware(r)))
}

/* table creation */

func createTables() {
	db.Exec(`
	CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		name TEXT,
		email TEXT UNIQUE,
		password TEXT,
		role TEXT,
		department TEXT,
        phone TEXT,
        address TEXT,
		photo_url TEXT,
		team_lead_id INT NULL,
        manager_id   INT NULL
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

/* signup/login */

func signup(w http.ResponseWriter, r *http.Request) {
	var u User
	json.NewDecoder(r.Body).Decode(&u)

	defaultRole := "unassigned" // default role for new users

	_, err := db.Exec(
		`INSERT INTO users 
		(name, email, password, role, department, phone, address)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		u.Name,
		u.Email,
		u.Password,
		defaultRole,
		u.Department,
		u.Phone,
		u.Address,
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
	err := json.NewDecoder(r.Body).Decode(&u)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Fetch user from DB
	var dbUser User
	err = db.QueryRow(
		`SELECT id, name, email, role, department, phone, address, photo_url
		FROM users
		WHERE email=$1 AND password=$2`,
		u.Email,
		u.Password,
	).Scan(
		&dbUser.ID,
		&dbUser.Name,
		&dbUser.Email,
		&dbUser.Role,
		&dbUser.Department,
		&dbUser.Phone,
		&dbUser.Address,
		&dbUser.PhotoURL,
	)

	if err != nil {
		log.Println("LOGIN ERROR:", err)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	log.Println("LOGIN SUCCESSFUL:", dbUser)

	// Generate JWT
	token, err := generateToken(dbUser)
	if err != nil {
		log.Println("JWT generation error:", err)
		http.Error(w, "Token generation failed", http.StatusInternalServerError)
		return
	}

	//log.Println("Generated JWT token:", token)

	// Return token + user
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"token": token,
		"user":  dbUser,
	})
}

func generateToken(user User) (string, error) {
	claims := jwt.MapClaims{
		"id":   user.ID,
		"role": user.Role,
		"exp":  time.Now().Add(time.Hour * 24).Unix(),
	}

	tokenObj := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := tokenObj.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

/* submit request*/

func createRequest(w http.ResponseWriter, r *http.Request) {
	var req Request
	json.NewDecoder(r.Body).Decode(&req)

	if req.EmployeeID == 0 || req.Content == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	var role string
	var teamLeadID *int64
	var managerID *int64

	err := db.QueryRow(
		`SELECT role, team_lead_id, manager_id FROM users WHERE id=$1`,
		req.EmployeeID,
	).Scan(&role, &teamLeadID, &managerID)

	if err != nil {
		http.Error(w, "Employee not found", http.StatusBadRequest)
		return
	}

	// determine workflow
	status := ""

	switch role {
	case "associate":
		if teamLeadID == nil {
			http.Error(w, "Team lead not assigned", http.StatusBadRequest)
			return
		}
		status = "pending_lead"

	case "lead":
		if managerID == nil {
			http.Error(w, "Manager not assigned", http.StatusBadRequest)
			return
		}
		status = "pending_manager"
		teamLeadID = nil

	case "manager":
		status = "approved"
		teamLeadID = nil
		managerID = nil

	default:
		http.Error(w, "Invalid role", http.StatusBadRequest)
		return
	}


	_, err = db.Exec(
		`INSERT INTO requests (employee_id, content, comment, status, lead_id, manager_id)
		VALUES ($1,$2,$3,$4,$5,$6)`,
		req.EmployeeID,
		req.Content,
		req.Comment,
		status,
		teamLeadID,
		managerID,
	)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
    
	fromEmail := "ranjithbemech14@gmail.com"   
	fromPassword := "xcog vlvn pmzh vwws" // Gmail App Password

	switch status {

	case "pending_lead":

		if teamLeadID == nil {
			break
		}

		leadEmail := getUserEmailByID(int(*teamLeadID))
		employeeName := getUserNameByID(req.EmployeeID)

		if leadEmail != "" {

			body := fmt.Sprintf(
				`Hello,

	A leave request has been submitted by:

	Employee: %s (%d)

	Request Details:
	----------------
	Leave Type : %s
	Status     : Pending Team Lead Approval

	Please review and take action.

	Thanks,
	Approval System`,
				employeeName,
				req.EmployeeID,
				req.Content,
			)

			go sendMail(
				fromEmail,
				fromPassword,
				[]string{leadEmail},
				nil,
				"New Leave Request Pending Approval",
				body,
			)
		}
	}


	json.NewEncoder(w).Encode(map[string]string{
		"message": "Leave request submitted successfully",
	})
}

func getRequests(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`
		SELECT 
			r.id, r.employee_id, u.name, r.content, r.status, r.lead_id, r.manager_id, r.comment, r.rejection_comment
		FROM requests r
		JOIN users u ON r.employee_id = u.id
	`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// create a struct with EmployeeName
	type RequestWithName struct {
		ID           int     `json:"id"`
		EmployeeID   int     `json:"employee_id"`
		EmployeeName string  `json:"employee_name"`
		Content      string  `json:"content"`
		Status       string  `json:"status"`
		LeadID       *int    `json:"lead_id"`
		ManagerID    *int    `json:"manager_id"`
		Comment      string  `json:"comment"`
		RejectionComment string `json:"rejection_comment"`

	}

	var list []RequestWithName

	for rows.Next() {
		var req RequestWithName
		var manager sql.NullInt32
		var rejection sql.NullString

		err := rows.Scan(
			&req.ID,
			&req.EmployeeID,
			&req.EmployeeName,
			&req.Content,
			&req.Status,
			&req.LeadID,
			&manager,
			&req.Comment,
			&rejection,
		)

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

	    if rejection.Valid {
			req.RejectionComment = rejection.String
		} else {
			req.RejectionComment = ""
		}

		if manager.Valid {
			req.ManagerID = new(int)
			*req.ManagerID = int(manager.Int32)
		} else {
			req.ManagerID = nil
		}
       // log.Printf("ID: %d, Comment: %s, Rejection: %s", req.ID, req.Comment, req.RejectionComment)

		list = append(list, req)
	}

	json.NewEncoder(w).Encode(list)
}

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

// Get all users (admin only)
func getUsers(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT id, name, email, role, department, phone, address, photo_url FROM users")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Name, &u.Email, &u.Role, &u.Department, &u.Phone, &u.Address,&u.PhotoURL); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		users = append(users, u)
	}

	json.NewEncoder(w).Encode(users)
}


// Delete user (admin only)
func deleteUser(w http.ResponseWriter, r *http.Request) {
    id, _ := strconv.Atoi(mux.Vars(r)["id"])

    //Check if user has requests
    rows, err := db.Query("SELECT id FROM requests WHERE employee_id=$1", id)
    if err != nil {
        log.Println("SELECT ERROR:", err)
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer rows.Close()

    requestIDs := []int{}
    for rows.Next() {
        var rid int
        rows.Scan(&rid)
        requestIDs = append(requestIDs, rid)
    }

    if len(requestIDs) > 0 {
        // User has request history, return message with request IDs
        json.NewEncoder(w).Encode(map[string]interface{}{
            "message":     "User has request history",
            "has_requests": true,
            "request_ids": requestIDs,
        })
        return
    }

    // delete user with no request histroy
    _, err = db.Exec("DELETE FROM users WHERE id=$1", id)
    if err != nil {
        log.Println("DELETE ERROR:", err)
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    json.NewEncoder(w).Encode(map[string]string{"message": "User deleted"})
}

//delete request and user
func deleteUserAndRequests(w http.ResponseWriter, r *http.Request) {
    id, _ := strconv.Atoi(mux.Vars(r)["id"])

    tx, err := db.Begin()
    if err != nil {
        log.Println("TX BEGIN ERROR:", err)
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Delete requests
    _, err = tx.Exec("DELETE FROM requests WHERE employee_id=$1", id)
    if err != nil {
        tx.Rollback()
        log.Println("DELETE REQUESTS ERROR:", err)
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Delete user
    _, err = tx.Exec("DELETE FROM users WHERE id=$1", id)
    if err != nil {
        tx.Rollback()
        log.Println("DELETE USER ERROR:", err)
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    tx.Commit()
    json.NewEncoder(w).Encode(map[string]string{"message": "User and requests deleted"})
}

func updateProfile(w http.ResponseWriter, r *http.Request) {
    id, _ := strconv.Atoi(mux.Vars(r)["id"])
    var payload struct {
        Name       string `json:"name"`
        Email      string `json:"email"`
        Role       string `json:"role"`       
        Department string `json:"department"` 
        Phone      string `json:"phone"`      
        Address    string `json:"address"`  
    }
    json.NewDecoder(r.Body).Decode(&payload)

    // Update role only if it is provided (admin)
    if payload.Role != "" {
        _, err := db.Exec(
            "UPDATE users SET name=$1, email=$2, role=$3, department=$4, phone=$5, address=$6 WHERE id=$7",
            payload.Name, payload.Email, payload.Role, payload.Department, payload.Phone, payload.Address, id,
        )
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
    } else {
        _, err := db.Exec(
            "UPDATE users SET name=$1, email=$2, department=$3, phone=$4, address=$5 WHERE id=$6",
            payload.Name, payload.Email, payload.Department, payload.Phone, payload.Address, id,
        )
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
    }

    json.NewEncoder(w).Encode(map[string]string{"message": "Profile updated"})
}


func authMiddleware(next http.HandlerFunc, roles ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing token", http.StatusUnauthorized)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "Invalid token format", http.StatusUnauthorized)
			return
		}

		tokenStr := parts[1]

		claims := jwt.MapClaims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		role, ok := claims["role"].(string)
		if !ok {
			http.Error(w, "Invalid token role", http.StatusUnauthorized)
			return
		}

		idFloat, ok := claims["id"].(float64)
		if !ok {
			http.Error(w, "Invalid token id", http.StatusUnauthorized)
			return
		}
		id := int(idFloat)

		// role checking
		if len(roles) > 0 {
			allowed := false
			for _, r := range roles {
				if r == role {
					allowed = true
				}
			}
			if !allowed {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}

		ctx := context.WithValue(r.Context(), "user", User{
			ID:   id,
			Role: role,
		})

		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func getMe(w http.ResponseWriter, r *http.Request) {
	userCtx, ok := r.Context().Value("user").(User)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var user User
	err := db.QueryRow(
		"SELECT id, name, email, role, department, phone, address, photo_url FROM users WHERE id=$1",
		userCtx.ID,
	).Scan(
		&user.ID,
		&user.Name,
		&user.Email,
		&user.Role,
		&user.Department,
		&user.Phone,
		&user.Address,
		&user.PhotoURL,
	)

	if err != nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	json.NewEncoder(w).Encode(user)
}


func createUserByAdmin(w http.ResponseWriter, r *http.Request) {

	err := r.ParseMultipartForm(10 << 20)
	if err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	// read form values
	name := r.FormValue("name")
	email := r.FormValue("email")
	department := r.FormValue("department")
	role := r.FormValue("role")
	teamLeadStr := r.FormValue("team_lead_id")
	managerStr := r.FormValue("manager_id")

	var teamLeadID *int64
	var managerID *int64

	//log.Printf("Creating user: name=%s, email=%s, role=%s, team_lead_id=%s, manager_id=%s\n",
    //name, email, role, teamLeadStr, managerStr)

    //log.Printf("Parsed IDs: teamLeadID=%v, managerID=%v\n", teamLeadID, managerID)

	if teamLeadStr != "" {
		id, err := strconv.ParseInt(teamLeadStr, 10, 64)
		if err != nil {
			http.Error(w, "Invalid team_lead_id", http.StatusBadRequest)
			return
		}
		teamLeadID = &id
	}

	if managerStr != "" {
		id, err := strconv.ParseInt(managerStr, 10, 64)
		if err != nil {
			http.Error(w, "Invalid manager_id", http.StatusBadRequest)
			return
		}
		managerID = &id
	}


	if name == "" || email == "" || department == "" || role == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	switch role {
	case "associate":
		if teamLeadID == nil || managerID == nil {
			http.Error(w, "Associate must have team lead and manager", http.StatusBadRequest)
			return
		}

	case "lead":
		if managerID == nil {
			http.Error(w, "Team lead must have a manager", http.StatusBadRequest)
			return
		}
		teamLeadID = nil

	case "manager", "admin":
		teamLeadID = nil
		managerID = nil

	default:
		http.Error(w, "Invalid role", http.StatusBadRequest)
		return
	}


	// Read photo
	file, handler, err := r.FormFile("photo")
	if err != nil {
		http.Error(w, "Photo is required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Create uploads folder if not exists
	uploadDir := "./uploads"
	if _, err := os.Stat(uploadDir); os.IsNotExist(err) {
		os.Mkdir(uploadDir, os.ModePerm)
	}

	//Generate filename with user id
	ext := filepath.Ext(handler.Filename)
	fileName := fmt.Sprintf("user_%d%s", time.Now().UnixNano(), ext)
	filePath := filepath.Join(uploadDir, fileName)

	//Save file
	dst, err := os.Create(filePath)
	if err != nil {
		http.Error(w, "Failed to save photo", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	_, err = io.Copy(dst, file)
	if err != nil {
		http.Error(w, "Failed to write photo", http.StatusInternalServerError)
		return
	}

	//DB insert
	defaultPassword := "123"
	defaultPhone := ""
	defaultAddress := ""
	photoURL := "/uploads/" + fileName

	_, err = db.Exec(`
		INSERT INTO users (name, email, password, role, department, phone, address, photo_url, team_lead_id, manager_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
	`,
		name,
		email,
		defaultPassword,
		role,
		department,
		defaultPhone,
		defaultAddress,
		photoURL,
		teamLeadID,
	    managerID,
	)

	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			http.Error(w, "Email already exists", http.StatusBadRequest)
			return
		}
		log.Println("CREATE USER ERROR:", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	//send mail
	go func() { 
		if err := sendUserCreationEmail(email, defaultPassword); err != nil {
			log.Println("Failed to send email to", email, ":", err)
		}
	}()


	json.NewEncoder(w).Encode(map[string]string{
		"message": "User created successfully",
	})
}


func sendUserCreationEmail(toEmail, tempPassword string) error {
	from := "ranjithbemech14@gmail.com"
	password := "xcog vlvn pmzh vwws" // Gmail App Password

	smtpHost := "smtp.gmail.com"
	smtpPort := "587"

	headers := ""
	headers += fmt.Sprintf("From: Admin Team <%s>\r\n", from)
	headers += fmt.Sprintf("To: <%s>\r\n", strings.TrimSpace(toEmail))
	headers += "Subject: Your Account Has Been Created\r\n"
	headers += "MIME-Version: 1.0\r\n"
	headers += "Content-Type: text/plain; charset=\"UTF-8\"\r\n"
	headers += "\r\n"

	body := fmt.Sprintf(`Hello,

Your account has been created by Admin.

Login details:
Email: %s
Temporary Password: %s

Please login and update your profile.

Login URL: http://localhost:3000

Thanks,
Admin Team
`, toEmail, tempPassword)

	message := []byte(headers + body)

	auth := smtp.PlainAuth("", from, password, smtpHost)

	return smtp.SendMail(
		smtpHost+":"+smtpPort,
		auth,
		from,
		[]string{toEmail},
		message,
	)
}


func updateProfilePhoto(w http.ResponseWriter, r *http.Request) {
	userCtx := r.Context().Value("user").(User)
    userID := userCtx.ID

	r.ParseMultipartForm(10 << 20)

	file, handler, err := r.FormFile("photo")
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"message": "Photo required"})
		return
	}
	defer file.Close()

	uploadDir := "./uploads"
	os.MkdirAll(uploadDir, os.ModePerm)

	ext := filepath.Ext(handler.Filename)
	fileName := fmt.Sprintf("user_%d_%d%s", userID, time.Now().UnixNano(), ext)

	dst, _ := os.Create(filepath.Join(uploadDir, fileName))
	defer dst.Close()
	io.Copy(dst, file)

	photoURL := "/uploads/" + fileName

	var user User
	db.QueryRow(`
		UPDATE users SET photo_url=$1 WHERE id=$2
		RETURNING id, name, email, role, department, photo_url
	`, photoURL, userID).
		Scan(&user.ID, &user.Name, &user.Email, &user.Role, &user.Department, &user.PhotoURL)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"user": user,
	})
}

func deleteProfilePhoto(w http.ResponseWriter, r *http.Request) {
	userCtx := r.Context().Value("user").(User)
    userID := userCtx.ID


	var user User
	db.QueryRow(`
		UPDATE users SET photo_url='' WHERE id=$1
		RETURNING id, name, email, role, department, photo_url
	`, userID).
		Scan(&user.ID, &user.Name, &user.Email, &user.Role, &user.Department, &user.PhotoURL)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"user": user,
	})
}

func changePassword(w http.ResponseWriter, r *http.Request) {
	userCtx := r.Context().Value("user").(User)

	var payload struct {
		OldPassword string `json:"oldPassword"`
		NewPassword string `json:"newPassword"`
	}

	json.NewDecoder(r.Body).Decode(&payload)

	// check old password
	var dbPassword string
	err := db.QueryRow(
		"SELECT password FROM users WHERE id=$1",
		userCtx.ID,
	).Scan(&dbPassword)

	if err != nil || dbPassword != payload.OldPassword {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Old password is incorrect",
		})
		return
	}

	// update password
	_, err = db.Exec(
		"UPDATE users SET password=$1 WHERE id=$2",
		payload.NewPassword,
		userCtx.ID,
	)
	if err != nil {
		http.Error(w, "Failed to update password", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"message": "Password updated successfully",
	})
}

func getUserEmailByID(id int) string {
	var email string
	err := db.QueryRow("SELECT email FROM users WHERE id=$1", id).Scan(&email)
	if err != nil {
		log.Println("Error fetching email for user:", id, err)
		return ""
	}
	return email
}

func getUserNameByID(id int) string {
	var name string
	err := db.QueryRow("SELECT name FROM users WHERE id=$1", id).Scan(&name)
	if err != nil {
		return ""
	}
	return name
}


func sendMail(from, password string, to []string, cc []string, subject, body string) error {
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"

	// combine all recipients for SMTP
	allRecipients := append(to, cc...)

	// build headers
	headers := ""
	headers += fmt.Sprintf("From: Admin Team <%s>\r\n", from)
	headers += fmt.Sprintf("To: %s\r\n", strings.Join(to, ","))
	if len(cc) > 0 {
		headers += fmt.Sprintf("Cc: %s\r\n", strings.Join(cc, ","))
	}
	headers += fmt.Sprintf("Subject: %s\r\n", subject)
	headers += "MIME-Version: 1.0\r\n"
	headers += "Content-Type: text/plain; charset=\"UTF-8\"\r\n"
	headers += "\r\n"

	message := []byte(headers + body)

	// setup authentication
	auth := smtp.PlainAuth("", from, password, smtpHost)

	// send mail
	return smtp.SendMail(smtpHost+":"+smtpPort, auth, from, allRecipients, message)
}

func leadAction(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(mux.Vars(r)["id"])
	if err != nil {
		http.Error(w, "Invalid request ID", http.StatusBadRequest)
		return
	}

	action := r.URL.Query().Get("action") // approve | reject

	// Get request details to use in emails
	var req Request
	err = db.QueryRow(`SELECT employee_id, lead_id, manager_id, comment, rejection_comment FROM requests WHERE id=$1`, id).
		Scan(&req.EmployeeID, &req.LeadID, &req.ManagerID, &req.Comment, &req.RejectionComment)
	if err != nil {
		http.Error(w, "Request not found", http.StatusNotFound)
		return
	}

	fromEmail := "ranjithbemech14@gmail.com"   
	fromPassword := "xcog vlvn pmzh vwws" // Gmail App Password

    employeeName := getUserNameByID(req.EmployeeID)

	switch action {
	case "approve":
		// Forward to manager
		_, err := db.Exec(`
			UPDATE requests
			SET status='pending_manager',
			    manager_id = (
			      SELECT manager_id
			      FROM users
			      WHERE id = requests.employee_id
			    )
			WHERE id = $1
		`, id)
		if err != nil {
			http.Error(w, "Failed to forward request", http.StatusInternalServerError)
			return
		}

		// Email: Send to manager, CC associate
		managerEmail := getUserEmailByID(*req.ManagerID)
		employeeEmail := getUserEmailByID(req.EmployeeID)

		subject := "Leave Request Pending Approval"
		body := fmt.Sprintf(
			"Hello,\n\n%s (ID: %d) has submitted a leave request: %s\n\nIt has been approved by the Team Lead and is pending your approval.\n\nThanks,\nApproval System",
			employeeName, req.EmployeeID, req.Content,
		)

		go sendMail(fromEmail, fromPassword, []string{managerEmail}, []string{employeeEmail}, subject, body)

	case "reject":
		var payload struct{ RejectionComment string `json:"rejection_comment"` }
		json.NewDecoder(r.Body).Decode(&payload)

		_, err := db.Exec(`
			UPDATE requests
			SET status='rejected by team lead', rejection_comment=$1
			WHERE id=$2
		`, payload.RejectionComment, id)
		if err != nil {
			http.Error(w, "Failed to reject request", http.StatusInternalServerError)
			return
		}

		// Email: Send to associate only, no CC
		employeeEmail := getUserEmailByID(req.EmployeeID)
		subject := "Leave Request Rejected by Team Lead"
		body := fmt.Sprintf(
			"Hello %s,\n\nYour leave request: %s has been rejected by the Team Lead.\n\nComment: %s\n\nThanks,\nApproval System",
			employeeName, req.Content, payload.RejectionComment,
		)

		go sendMail(fromEmail, fromPassword, []string{employeeEmail}, nil, subject, body)


	default:
		http.Error(w, "Invalid action", http.StatusBadRequest)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"message": "Action completed",
	})
}


func managerAction(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(mux.Vars(r)["id"])
	if err != nil {
		http.Error(w, "Invalid request ID", http.StatusBadRequest)
		return
	}

	action := r.URL.Query().Get("action") // approve | reject

	// Get request details
	var req Request
	err = db.QueryRow(`SELECT employee_id, lead_id, manager_id, comment FROM requests WHERE id=$1`, id).
		Scan(&req.EmployeeID, &req.LeadID, &req.ManagerID, &req.Comment)
	if err != nil {
		http.Error(w, "Request not found", http.StatusNotFound)
		return
	}

	fromEmail := "ranjithbemech14@gmail.com"   
	fromPassword := "xcog vlvn pmzh vwws" // Gmail App Password

	employeeName := getUserNameByID(req.EmployeeID)

	switch action {
	case "approve":
		_, err := db.Exec("UPDATE requests SET status='approved by manager' WHERE id=$1", id)
		if err != nil {
			http.Error(w, "Failed to approve request", http.StatusInternalServerError)
			return
		}

		// Email: Notify associate, CC team lead
		employeeEmail := getUserEmailByID(req.EmployeeID)
		var cc []string
		if req.LeadID != nil {
			cc = []string{getUserEmailByID(*req.LeadID)}
		}

		subject := "Leave Request Approved by Manager"
		body := fmt.Sprintf(
			"Hello %s,\n\nYour leave request: %s has been approved by the Manager.\n\nThanks,\nApproval System",
			employeeName, req.Content,
		)

		go sendMail(fromEmail, fromPassword, []string{employeeEmail}, cc, subject, body)


	case "reject":
		var payload struct{ RejectionComment string `json:"rejection_comment"` }
		json.NewDecoder(r.Body).Decode(&payload)

		_, err := db.Exec("UPDATE requests SET status='rejected by manager', rejection_comment=$1 WHERE id=$2", payload.RejectionComment, id)
		if err != nil {
			http.Error(w, "Failed to reject request", http.StatusInternalServerError)
			return
		}

		// Email: Notify associate, CC team lead
		employeeEmail := getUserEmailByID(req.EmployeeID)
		var cc []string
		if req.LeadID != nil {
			cc = []string{getUserEmailByID(*req.LeadID)}
		}

		subject := "Leave Request Rejected by Manager"
		body := fmt.Sprintf(
			"Hello %s,\n\nYour leave request: %s has been rejected by the Manager.\n\nComment: %s\n\nThanks,\nApproval System",
			employeeName, req.Content, payload.RejectionComment,
		)

		go sendMail(fromEmail, fromPassword, []string{employeeEmail}, cc, subject, body)



	default:
		http.Error(w, "Invalid action", http.StatusBadRequest)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"message": "Action completed",
	})
}


func updateRequest(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(mux.Vars(r)["id"])
	if err != nil {
		http.Error(w, "Invalid request ID", http.StatusBadRequest)
		return
	}

	var payload struct {
		Content string `json:"content"`
		Comment string `json:"comment"`
	}

	json.NewDecoder(r.Body).Decode(&payload)

	if payload.Content == "" {
		http.Error(w, "Content is required", http.StatusBadRequest)
		return
	}

	// Get existing request + employee info
	var employeeID int
	var status string
	var role string
	var teamLeadID *int64
	var managerID *int64

	err = db.QueryRow(`
		SELECT r.employee_id, r.status, u.role, u.team_lead_id, u.manager_id
		FROM requests r
		JOIN users u ON u.id = r.employee_id
		WHERE r.id = $1
	`, id).Scan(&employeeID, &status, &role, &teamLeadID, &managerID)

	if err != nil {
		http.Error(w, "Request not found", http.StatusNotFound)
		return
	}

	// Allow edit ONLY if rejected
	if !strings.HasPrefix(status, "rejected") {
		http.Error(w, "Only rejected requests can be edited", http.StatusForbidden)
		return
	}

	// Reset workflow
	newStatus := ""

	switch role {
	case "associate":
		if teamLeadID == nil {
			http.Error(w, "Team lead not assigned", http.StatusBadRequest)
			return
		}
		newStatus = "pending_lead"

	case "lead":
		if managerID == nil {
			http.Error(w, "Manager not assigned", http.StatusBadRequest)
			return
		}
		newStatus = "pending_manager"
		teamLeadID = nil

	case "manager":
		newStatus = "approved"
		teamLeadID = nil
		managerID = nil
	}

	// Update same request
	_, err = db.Exec(`
		UPDATE requests
		SET content=$1,
		    comment=$2,
		    status=$3,
		    lead_id=$4,
		    manager_id=$5,
			rejection_comment=$6
		WHERE id=$7
	`,
		payload.Content,
		payload.Comment,
		newStatus,
		teamLeadID,
		managerID,
		"",
		id,
	)

	if err != nil {
		log.Println("Failed to update request:", err)
		http.Error(w, "Failed to update request", http.StatusInternalServerError)
		return
	}

	// ---- MAIL (only when pending_lead) ----
	if newStatus == "pending_lead" && teamLeadID != nil {

		fromEmail := "ranjithbemech14@gmail.com"
		fromPassword := "xcog vlvn pmzh vwws"

		leadEmail := getUserEmailByID(int(*teamLeadID))
		employeeName := getUserNameByID(employeeID)

		if leadEmail != "" {
			body := fmt.Sprintf(
				`Hello,

A leave request has been UPDATED and RESUBMITTED by:

Employee: %s (%d)

Request Details:
----------------
Leave Type : %s
Status     : Pending Team Lead Approval

Please review and take action.

Thanks,
Approval System`,
				employeeName,
				employeeID,
				payload.Content,
			)

			go sendMail(
				fromEmail,
				fromPassword,
				[]string{leadEmail},
				nil,
				"Resubmitted Leave Request Pending Approval",
				body,
			)
		}
	}

	json.NewEncoder(w).Encode(map[string]string{
		"message": "Leave request updated and resubmitted successfully",
	})
}
