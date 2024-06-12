package utils

import (
	"net/smtp"
	"os"
)

func SendMailSimple(email, subject, message string) error {
	from := os.Getenv("EMAIL_FROM")
	password := os.Getenv("EMAIL_PASSWORD")

	addr := "smtp.gmail.com:587"
	to := []string{email}

	smsg := "Subject: " + subject + "\r\n\r\n" + message

	auth := smtp.PlainAuth(
		"", // Identity
		from,
		password,         // password
		"smtp.gmail.com", // host
	)

	err := smtp.SendMail(addr, auth, from, to, []byte(smsg))

	return err
}
