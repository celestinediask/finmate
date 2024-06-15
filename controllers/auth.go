package controllers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"finmate/database"
	"finmate/models"
	"finmate/utils"

	"net/http"
	"os"

	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

var JWTSecret = []byte(os.Getenv("JWT_KEY"))

func Signup(w http.ResponseWriter, r *http.Request) {

	var user models.User

	// bind json req to user struct
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}

	// hash password
	hashedPassword, err := HashPassword(user.Password)
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

	otp := generateOTP()
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

	if match := CheckPasswordHash(req.Password, user.Password); !match {
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

// func UserAuthMiddleware() gin.HandlerFunc {
// 	return func(c *gin.Context) {
// 		jwtSecret := os.Getenv("JWT_SECRET")
// 		if jwtSecret == "" {
// 			c.JSON(http.StatusInternalServerError, gin.H{"error": "JWT secret is missing"})
// 			c.Abort()
// 			return
// 		}

// 		jwtToken := c.GetHeader("Authorization")
// 		if jwtToken == "" {
// 			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is missing"})
// 			c.Abort()
// 			return
// 		}

// 		// Ensure the token format is correct
// 		if !strings.HasPrefix(jwtToken, "Bearer ") {
// 			c.JSON(http.StatusUnauthorized, gin.H{"error": "bearer token is missing"})
// 			c.Abort()
// 			return
// 		}

// 		// Extract the token string (excluding the "Bearer " prefix)
// 		tokenString := jwtToken[7:]

// 		// Validate the JWT token
// 		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
// 			return []byte(jwtSecret), nil
// 		})
// 		if err != nil || !token.Valid {
// 			// Log the error for debugging
// 			fmt.Println("Token validation error:", err)
// 			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
// 			c.Abort()
// 			return
// 		}

// 		// Check token expiration
// 		claims, ok := token.Claims.(jwt.MapClaims)
// 		if !ok || !token.Valid {
// 			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
// 			c.Abort()
// 			return
// 		}

// 		expirationTime := time.Unix(int64(claims["exp"].(float64)), 0)
// 		if time.Now().After(expirationTime) {
// 			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token has expired"})
// 			c.Abort()
// 			return
// 		}

// 		// Set claims in context for further processing
// 		c.Set("username", claims["username"])
// 		c.Set("email", claims["email"])

// 		// Proceed to the next middleware or handler
// 		c.Next()
// 	}
// }

func UserAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwtSecret := os.Getenv("JWT_SECRET")
		if jwtSecret == "" {
			http.Error(w, "JWT secret is missing", http.StatusInternalServerError)
			return
		}

		jwtToken := r.Header.Get("Authorization")
		if jwtToken == "" {
			http.Error(w, "Authorization header is missing", http.StatusUnauthorized)
			return
		}

		// Ensure the token format is correct
		if !strings.HasPrefix(jwtToken, "Bearer ") {
			http.Error(w, "Bearer token is missing", http.StatusUnauthorized)
			return
		}

		// Extract the token string (excluding the "Bearer " prefix)
		tokenString := jwtToken[7:]

		// Validate the JWT token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(jwtSecret), nil
		})
		if err != nil || !token.Valid {
			// Log the error for debugging
			fmt.Println("Token validation error:", err)
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Check token expiration
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		expirationTime := time.Unix(int64(claims["exp"].(float64)), 0)
		if time.Now().After(expirationTime) {
			http.Error(w, "Token has expired", http.StatusUnauthorized)
			return
		}

		// Set claims in context for further processing
		ctx := context.WithValue(r.Context(), "username", claims["username"])
		ctx = context.WithValue(ctx, "email", claims["email"])

		// Proceed to the next middleware or handler
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

/*
	func UserAuthMiddleware() gin.HandlerFunc {
		return func(c *gin.Context) {

			jwtSecret := os.Getenv("JWT_SECRET")
			if jwtSecret == "" {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "jwt secret is missing"})
				c.Abort()
				return
			}

			jwtToken := c.GetHeader("Authorization")
			if jwtToken == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "auth header is missing"})
				c.Abort()
				return
			}

			// Validate the JWT token
			token, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
				return []byte(jwtSecret), nil
			})
			if err != nil || !token.Valid {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
				c.Abort()
				return
			}

			// check if token expired
			if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
				username := claims["username"]
				email := claims["email"]
				c.Set("username", username)
				c.Set("email", email)
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Session expired please login again"})
				c.Abort()
				return
			}

			//c.JSON(http.StatusOK, gin.H{"token": jwtToken})

			c.Next()
		}
	}
*/
/*




 */

func Validate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "I'm logged in"})
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func generateOTP() string {
	return fmt.Sprintf("%06d", rand.Intn(1000000))
}
