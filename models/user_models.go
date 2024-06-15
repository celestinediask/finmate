package models

import (
	"time"
)

type User struct {
	ID            uint   `json:"id"`
	Username      string `json:"username" binding:"required"`
	Email         string `json:"email" binding:"required"`
	Password      string `json:"password" binding:"required"`
	EmailVerified bool   `json:"is_email_verified"`
	IsAdmin       bool
}

type UserResponse struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

type SendOTPEmailReq struct {
	Email string `json:"email" binding:"required"`
}

type VerifyEmailReq struct {
	Email string `json:"email" binding:"required"`
	OTP   string `json:"otp" binding:"required"`
}

type LoginReq struct {
	UsernameOrEmail string `json:"username_or_email" binding:"required"`
	Password        string `json:"password" binding:"required"`
}

type OTPDetails struct {
	OTP       string `json:"otp"`
	ExpiresAt time.Time
}

type Record struct {
	ID            int     `json:"id"`
	Amount        float64 `json:"amount"`
	Description   string  `json:"description"`
	Category      string  `json:"category"`
	PaymentMethod string  `json:"payment_method"`
}
