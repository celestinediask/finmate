package config

import (
	"log"
	"os"

	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
)

var Store *sessions.CookieStore

func LoadEnv() {

	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

}

func SetupSession() {
	var session_key = os.Getenv("SESSION_KEY")
	var sessionKey = []byte(session_key)
	Store = sessions.NewCookieStore(sessionKey)
}
