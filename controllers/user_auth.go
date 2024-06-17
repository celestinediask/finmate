package controllers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"finmate/database"
	"finmate/models"
	"finmate/utils"

	"net/http"
	"os"

	"github.com/golang-jwt/jwt"
)

var JWTSecret = []byte(os.Getenv("JWT_KEY"))

func Signup(w http.ResponseWriter, r *http.Request) {

	var user models.User

	// bind json req to user struct
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}

	// hash password
	hashedPassword, err := utils.HashPassword(user.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}

	user.Password = hashedPassword

	// create user
	stmt := "INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id"
	err = database.DB.QueryRow(stmt, user.Username, user.Email, user.Password).Scan(&user.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	userResponse := models.UserResponse{
		ID:       user.ID,
		Username: user.Username,
		Email:    user.Email,
	}

	// Set response status and return user ID
	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userResponse)
}
func SendOTPEmail(w http.ResponseWriter, r *http.Request) {

	var req models.SendOTPEmailReq
	var user models.User

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}

	err := database.DB.QueryRow("SELECT email, is_email_verified FROM users WHERE email = $1", req.Email).Scan(&user.Email, &user.EmailVerified)
	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Fprintf(w, "User not found for email: %s", req.Email)
			http.Error(w, "User not signed up", http.StatusInternalServerError)
		} else {
			fmt.Fprintf(w, "Database query failed: %v", err)
			http.Error(w, "Database query failed", http.StatusInternalServerError)
		}
		return
	}

	if user.EmailVerified {
		http.Error(w, "Email already verified", http.StatusBadRequest)
		return
	}

	otp := utils.GenerateOTP()
	if otp == "" {
		http.Error(w, "OTP generation failed", http.StatusInternalServerError)
		return
	}

	email := req.Email

	utils.EmailOTPDetails[email] = models.OTPDetails{
		OTP:       otp,
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	// Send OTP via email
	subject := "Your OTP Code"
	message := fmt.Sprintf("Your OTP code is: %s", otp)

	if err := utils.SendMailSimple(email, subject, message); err != nil {
		http.Error(w, "sending email failed", http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "successfully send otp to the email"}`))
}

func VerifyEmail(w http.ResponseWriter, r *http.Request) {

	var req models.VerifyEmailReq
	var user models.User

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	email := req.Email
	OTPDetails := utils.EmailOTPDetails[email]
	storedOTP := OTPDetails.OTP
	OTPExp := OTPDetails.ExpiresAt

	// check if user exists
	err := database.DB.QueryRow("SELECT email, is_email_verified FROM users WHERE email = $1", email).Scan(&user.Email, &user.EmailVerified)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "User not signed up", http.StatusInternalServerError)
		} else {
			http.Error(w, "Database error", http.StatusInternalServerError)
		}
		return
	}

	if user.EmailVerified {
		http.Error(w, "Email already verified", http.StatusBadRequest)
		return
	}

	if storedOTP == "" {
		http.Error(w, "OTP not generated for this email", http.StatusBadRequest)
		return
	}

	if !time.Now().Before(OTPExp) {
		http.Error(w, "OTP expired", http.StatusUnauthorized)
		return
	}

	if req.OTP != storedOTP {
		http.Error(w, "Invalid otp", http.StatusOK)
		return
	}

	//user.EmailVerified = true
	_, err = database.DB.Exec("UPDATE users SET is_email_verified = $1 WHERE email = $2", true, email)
	if err != nil {
		http.Error(w, "Failed to verify user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "email verified"})
}

func Login(w http.ResponseWriter, r *http.Request) {

	var req models.LoginReq
	var user models.User

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Check for empty email and password
	if req.UsernameOrEmail == "" || req.Password == "" {
		http.Error(w, "Username/Email and password cannot be empty", http.StatusBadRequest)
		return
	}

	// Check if username or email exists
	query := "SELECT username, email, password, is_email_verified FROM users WHERE email = $1 OR username = $2"
	row := database.DB.QueryRow(query, req.UsernameOrEmail, req.UsernameOrEmail)
	err := row.Scan(&user.Username, &user.Email, &user.Password, &user.EmailVerified)
	if err == sql.ErrNoRows {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Check if the email is verified
	if !user.EmailVerified {
		http.Error(w, "Email is not verified", http.StatusUnauthorized)
		return
	}

	if match := utils.CheckPasswordHash(req.Password, user.Password); !match {
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	// Fetch the JWT secret from the environment variable
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		http.Error(w, "JWT secret not provided", http.StatusInternalServerError)
		return
	}

	// set claims in token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": user.Username,
		"email":    user.Email,
		"exp":      time.Now().Add(time.Hour * 72).Unix(),
	})

	tokenString, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

func Validate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "I'm logged in"})
}
