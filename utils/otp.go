package utils

import (
	"database/sql"
	"encoding/json"
	"finmate/database"
	"finmate/models"
	"fmt"
	"math/rand"
	"net/http"
	"time"
)

// temp map to store email and OTP details
var EmailOTPDetails = make(map[string]models.OTPDetails)

func GenerateOTP() string {
	return fmt.Sprintf("%06d", rand.Intn(1000000))
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

	otp := GenerateOTP()
	if otp == "" {
		http.Error(w, "OTP generation failed", http.StatusInternalServerError)
		return
	}

	email := req.Email

	EmailOTPDetails[email] = models.OTPDetails{
		OTP:       otp,
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	// Send OTP via email
	subject := "Your OTP Code"
	message := fmt.Sprintf("Your OTP code is: %s", otp)

	if err := SendMailSimple(email, subject, message); err != nil {
		http.Error(w, "sending email failed", http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "successfully send otp to the email"}`))
}
