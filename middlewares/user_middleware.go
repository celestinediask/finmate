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

func UserAuthMiddleware(next http.Handler) http.Handler {
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

		if !strings.HasPrefix(jwtToken, "Bearer ") {
			http.Error(w, "Bearer token is missing", http.StatusUnauthorized)
			return
		}

		tokenString := jwtToken[7:]

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(jwtSecret), nil
		})
		if err != nil || !token.Valid {
			fmt.Println("Token validation error:", err)
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

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

		userid := claims["userid"].(float64)

		var isAdmin bool
		err = db.QueryRow("SELECT is_admin FROM users WHERE id=$1", userid).Scan(&isAdmin)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, "User not found", http.StatusUnauthorized)
			} else {
				http.Error(w, "Database query error", http.StatusInternalServerError)
			}
			return
		}

		if isAdmin {
			http.Error(w, "User is admin, no user access rights", http.StatusForbidden)
			return
		}

		// Set claims in context for further processing
		ctx := context.WithValue(r.Context(), "userid", claims["userid"])

		// Proceed to the next middleware or handler
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
