package middlewares

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
)

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
