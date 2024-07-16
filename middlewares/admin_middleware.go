package middlewares

import (
	"context"
	"database/sql"
	"finmate/database"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
)

func AdminAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		db := database.DB

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

		// Extract username from claims
		username := claims["username"].(string)

		// Query to check if the user is an admin
		var isAdmin bool
		err = db.QueryRow("SELECT is_admin FROM users WHERE username=$1", username).Scan(&isAdmin)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, "User not found", http.StatusUnauthorized)
			} else {
				http.Error(w, "Database query error", http.StatusInternalServerError)
			}
			return
		}

		if !isAdmin {
			http.Error(w, "User is not an admin", http.StatusForbidden)
			return
		}

		// Set claims in context for further processing
		ctx := context.WithValue(r.Context(), "username", username)
		ctx = context.WithValue(ctx, "email", claims["email"])

		// Proceed to the next middleware or handler
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
