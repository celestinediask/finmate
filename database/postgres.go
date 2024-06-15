package database

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/lib/pq"
)

var DB *sql.DB

func ConnectDB() {

	host := os.Getenv("DB_HOST")
	port := os.Getenv("DB_PORT")
	user := os.Getenv("DB_USER")
	password := os.Getenv("DB_PASSWORD")
	dbname := os.Getenv("DB_NAME")

	psqlInfo := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)
	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		panic("failed to connect database")
	}
	DB = db
	fmt.Println("Successfully connected to db")
}

func CreateDatabase() {
	// Check if the database exists
	var exists bool
	err := DB.QueryRow("SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)", "boo").Scan(&exists)
	if err != nil {
		log.Fatal(err)
	}

	if !exists {
		// Create the database
		_, err := DB.Exec("CREATE DATABASE finmate")
		if err != nil {
			log.Fatal(err)
		}
		log.Println("Database finmate created successfully")
	} else {
		log.Println("Database finmate already exists")
	}
}

func MigrateTable() {
	sqlScript, err := os.ReadFile("database/migration.sql")
	if err != nil {
		log.Fatal(err)
	}

	_, err = DB.Exec(string(sqlScript))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Successfully migrated tables")
}
