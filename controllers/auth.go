package controllers

import (
	"database/sql"
	"encoding/json"
	"time"

	"finmate/database"
	"finmate/models"
	"finmate/utils"

	"net/http"
	"os"

	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt"
)

var JWTSecret = []byte(os.Getenv("JWT_KEY"))

var validate *validator.Validate

func Signup(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var user models.User

	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	validate = validator.New()
	if err := validate.Struct(user); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	hashedPassword, err := utils.HashPassword(user.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}

	user.Password = hashedPassword

	stmt := "INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id"
	err = database.DB.QueryRow(stmt, user.Username, user.Email, user.Password).Scan(&user.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := models.UserResponse{
		ID:       user.ID,
		Username: user.Username,
		Email:    user.Email,
		Password: "",
	}

	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func VerifyEmail(w http.ResponseWriter, r *http.Request) {

	var req models.VerifyEmailReq
	var user models.User

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	email := req.Email
	OTPDetails := utils.EmailOTPDetails[email]
	storedOTP := OTPDetails.OTP
	OTPExp := OTPDetails.ExpiresAt

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

	validate = validator.New()
	if err := validate.Struct(req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// if req.UsernameOrEmail == "" || req.Password == "" {
	// 	http.Error(w, "username_or_email and password cannot be empty", http.StatusBadRequest)
	// 	return
	// }

	query := "SELECT id, username, email, password, is_email_verified FROM users WHERE email = $1 OR username = $2"
	row := database.DB.QueryRow(query, req.UsernameOrEmail, req.UsernameOrEmail)
	err := row.Scan(&user.ID, &user.Username, &user.Email, &user.Password, &user.EmailVerified)
	if err == sql.ErrNoRows {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if !user.EmailVerified {
		http.Error(w, "Email is not verified", http.StatusUnauthorized)
		return
	}

	if match := utils.CheckPasswordHash(req.Password, user.Password); !match {
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		http.Error(w, "JWT secret not provided", http.StatusInternalServerError)
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userid": user.ID,
		"exp":    time.Now().Add(time.Hour * 72).Unix(),
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
