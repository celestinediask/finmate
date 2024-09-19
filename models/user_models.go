package models

import (
	"time"
)

type User struct {
	ID            uint   `json:"id"`
	Username      string `json:"username" validate:"required,alphanum,min=3,max=15"`
	Email         string `json:"email" validate:"required,email"`
	Password      string `json:"password" validate:"required,min=3"`
	EmailVerified bool   `json:"is_email_verified"`
	IsAdmin       bool
}

type UserResponse struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type SendOTPEmailReq struct {
	Email string `json:"email" binding:"required"`
}

type VerifyEmailReq struct {
	Email string `json:"email" binding:"required"`
	OTP   string `json:"otp" binding:"required"`
}

type LoginReq struct {
	UsernameOrEmail string `json:"username_or_email" validate:"required"`
	Password        string `json:"password" validate:"required"`
}

type OTPDetails struct {
	OTP       string `json:"otp"`
	ExpiresAt time.Time
}

type Record struct {
	ID            int       `json:"id"`
	Amount        float64   `json:"amount"`
	Description   string    `json:"description"`
	Category      string    `json:"category"`
	PaymentMethod string    `json:"payment_method"`
	CreatedAt     time.Time `json:"created_at"`
}

type Transaction struct {
	ID        int    `json:"id"`
	OrderID   string `json:"order_id"`
	PaymentID string `json:"payment_id"`
	Status    string `json:"status"`
	Amount    int    `json:"amount"`
}
