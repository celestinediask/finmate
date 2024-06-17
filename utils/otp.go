package utils

import (
	"finmate/models"
	"fmt"
	"math/rand"
)

// temp map to store email and OTP details
var EmailOTPDetails = make(map[string]models.OTPDetails)

func GenerateOTP() string {
	return fmt.Sprintf("%06d", rand.Intn(1000000))
}
