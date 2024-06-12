package controllers

import (
	"finmate/database"
	"finmate/models"
	"finmate/utils"
	"math/rand"
	"strings"

	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

var JWTSecret = []byte(os.Getenv("JWT_KEY"))

func Signup(c *gin.Context) {

	var user models.User

	// bind json req to user struct
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if username or email already exists
	if err := database.DB.Where("username = ? OR email = ?", user.Username, user.Email).First(&user).Error; err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Username or email already exists"})
		return
	}

	hashedPassword, err := HashPassword(user.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash password"})
	}

	user.Password = hashedPassword

	if result := database.DB.Create(&user); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error creating user"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "Signup successful! Proceed to verify your email."})
}

func SendOTPEmail(c *gin.Context) {

	var req models.SendOTPEmailReq

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// check if user exists
	var user models.User
	if err := database.DB.Where("email = ?", req.Email).First(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User not signed up"})
		return
	}

	if user.EmailVerified {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email already verified"})
		return
	}

	otp := generateOTP()
	if otp == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "OTP generation failed"})
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "sending email failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "successfully send otp to the email"})

}

func VerifyEmail(c *gin.Context) {

	var req models.VerifyEmailReq

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	email := req.Email
	OTPDetails := utils.EmailOTPDetails[email]
	storedOTP := OTPDetails.OTP
	OTPExp := OTPDetails.ExpiresAt

	// check if user exists
	var user models.User
	if err := database.DB.Where("email = ?", email).First(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User not signed up"})
		return
	}

	if user.EmailVerified {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email already verified"})
		return
	}

	if storedOTP == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "OTP not generated for this email"})
		return
	}

	if !time.Now().Before(OTPExp) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "OTP expired"})
		return
	}

	if req.OTP != storedOTP {
		c.JSON(http.StatusOK, gin.H{"error": "Invalid otp"})
		return
	}

	user.EmailVerified = true
	if err := database.DB.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "email verified"})

}

func Login(c *gin.Context) {

	var req = models.LoginReq{}
	var user models.User

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check for empty email and password
	if req.UsernameOrEmail == "" || req.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email and password cannot be empty"})
		return
	}

	// check if username or email exists
	if database.DB.Where("email = ? OR username = ?", req.UsernameOrEmail, req.UsernameOrEmail).First(&user).Error != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	if match := CheckPasswordHash(req.Password, user.Password); !match {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Ivalid password"})
		return
	}

	// Fetch the JWT secret from the environment variable
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "JWT secret not provided"})
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
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

func UserAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		jwtSecret := os.Getenv("JWT_SECRET")
		if jwtSecret == "" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "JWT secret is missing"})
			c.Abort()
			return
		}

		jwtToken := c.GetHeader("Authorization")
		if jwtToken == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is missing"})
			c.Abort()
			return
		}

		// Ensure the token format is correct
		if !strings.HasPrefix(jwtToken, "Bearer ") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "bearer token is missing"})
			c.Abort()
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
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Check token expiration
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		expirationTime := time.Unix(int64(claims["exp"].(float64)), 0)
		if time.Now().After(expirationTime) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token has expired"})
			c.Abort()
			return
		}

		// Set claims in context for further processing
		c.Set("username", claims["username"])
		c.Set("email", claims["email"])

		// Proceed to the next middleware or handler
		c.Next()
	}
}

func Validate(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "token validated"})
}

func Logout(c *gin.Context) {

	c.SetCookie("jwt_token", "", -1, "/", "localhost", false, true)
	c.Redirect(http.StatusFound, "/login")
}

func generateOTP() string {
	return fmt.Sprintf("%06d", rand.Intn(1000000))
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
