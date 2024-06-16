package controllers

import (
	"database/sql"
	"encoding/json"
	"finmate/database"
	"finmate/models"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi"
)

func Profile(w http.ResponseWriter, r *http.Request) {
	// Retrieve the username from the context
	username, ok := r.Context().Value("username").(string)
	if !ok {
		http.Error(w, "Unable to retrieve username from context", http.StatusInternalServerError)
		return
	}

	var user models.User

	// Query to get user details
	query := "SELECT username, email, is_email_verified FROM users WHERE username = $1"
	err := database.DB.QueryRow(query, username).Scan(&user.Username, &user.Email, &user.EmailVerified)
	if err == sql.ErrNoRows {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return user details as JSON
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(user)
}

func AddRecord(w http.ResponseWriter, r *http.Request) {
	var record models.Record
	if err := json.NewDecoder(r.Body).Decode(&record); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	query := `INSERT INTO records (amount, description, category, payment_method) VALUES ($1, $2, $3, $4) RETURNING id`
	err := database.DB.QueryRow(query, record.Amount, record.Description, record.Category, record.PaymentMethod).Scan(&record.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(record)
}

func ListRecords(w http.ResponseWriter, r *http.Request) {
	var records []models.Record

	query := `SELECT id, amount, description, category, payment_method FROM records`
	rows, err := database.DB.Query(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var record models.Record
		if err := rows.Scan(&record.ID, &record.Amount, &record.Description, &record.Category, &record.PaymentMethod); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		records = append(records, record)
	}

	if err := rows.Err(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(records)
}

func EditRecord(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var record models.Record

	query := `SELECT id, amount, description, category, payment_method FROM records WHERE id = $1`
	err := database.DB.QueryRow(query, id).Scan(&record.ID, &record.Amount, &record.Description, &record.Category, &record.PaymentMethod)
	if err != nil {
		http.Error(w, "Record not found", http.StatusNotFound)
		return
	}

	if err := json.NewDecoder(r.Body).Decode(&record); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	updateQuery := `
		UPDATE records 
		SET amount = $1, description = $2, category = $3, payment_method = $4 
		WHERE id = $5
	`
	_, err = database.DB.Exec(updateQuery, record.Amount, record.Description, record.Category, record.PaymentMethod, record.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(record)
}

func DeleteRecord(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var exists bool
	db := database.DB
	// Check if the record exists
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM records WHERE id = $1)", id).Scan(&exists)
	if err != nil {
		http.Error(w, `{"error": "Database error"}`, http.StatusInternalServerError)
		log.Println("Error checking if record exists:", err)
		return
	}

	if !exists {
		http.Error(w, `{"error": "Record not found"}`, http.StatusNotFound)
		return
	}

	// Delete the record
	_, err = db.Exec("DELETE FROM records WHERE id = $1", id)
	if err != nil {
		http.Error(w, `{"error": "Failed to delete record"}`, http.StatusInternalServerError)
		log.Println("Error deleting record:", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "Record deleted successfully"}`))
}

func GetRecordByID(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var record models.Record
	db := database.DB

	err := db.QueryRow("SELECT id, amount, description, category, payment_method FROM records WHERE id = $1", id).Scan(&record.ID, &record.Amount, &record.Description, &record.Category, &record.PaymentMethod)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, `{"error": "Record not found"}`, http.StatusNotFound)
			return
		}
		http.Error(w, `{"error": "Database error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(record)
}

func SearchRecords(w http.ResponseWriter, r *http.Request) {
	var records []models.Record
	db := database.DB
	query := r.URL.Query()
	queryStrings := make([]string, 0, len(query))

	args := make([]interface{}, 0, len(query))

	for key, value := range query {
		queryStrings = append(queryStrings, key+" = $"+strconv.Itoa(len(args)+1))
		args = append(args, value[0])
	}

	queryString := "SELECT id, amount, description, category, payment_method FROM records"
	if len(queryStrings) > 0 {
		queryString += " WHERE " + strings.Join(queryStrings, " AND ")
	}

	rows, err := db.Query(queryString, args...)
	if err != nil {
		http.Error(w, `{"error": "Database error"}`, http.StatusInternalServerError)
		log.Println("Error querying records:", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var record models.Record
		err := rows.Scan(&record.ID, &record.Amount, &record.Description, &record.Category, &record.PaymentMethod)
		if err != nil {
			http.Error(w, `{"error": "Error scanning records"}`, http.StatusInternalServerError)
			log.Println("Error scanning record:", err)
			return
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		http.Error(w, `{"error": "Error iterating over records"}`, http.StatusInternalServerError)
		log.Println("Error iterating over rows:", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(records)
}

func CountRecords(w http.ResponseWriter, r *http.Request) {
	var count int64
	db := database.DB
	err := db.QueryRow("SELECT COUNT(*) FROM records").Scan(&count)
	if err != nil {
		http.Error(w, `{"error": "Database error"}`, http.StatusInternalServerError)
		log.Println("Error counting records:", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int64{"count": count})
}

func SortRecords(w http.ResponseWriter, r *http.Request) {
	sortBy := r.URL.Query().Get("sort_by")
	order := r.URL.Query().Get("order")
	db := database.DB

	if sortBy == "" || order == "" {
		http.Error(w, `{"error": "sort_by and order query parameters are required"}`, http.StatusBadRequest)
		return
	}

	// Validate order parameter
	if order != "asc" && order != "desc" {
		http.Error(w, `{"error": "order must be 'asc' or 'desc'"}`, http.StatusBadRequest)
		return
	}

	// Construct SQL query
	queryString := "SELECT id, amount, description, category, payment_method, created_at FROM records ORDER BY " + sortBy + " " + order
	rows, err := db.Query(queryString)
	if err != nil {
		http.Error(w, `{"error": "Database error"}`, http.StatusInternalServerError)
		log.Println("Error querying records:", err)
		return
	}
	defer rows.Close()

	// Slice to store records
	var records []models.Record

	// Iterate through rows and scan into records slice
	for rows.Next() {
		var record models.Record
		err := rows.Scan(&record.ID, &record.Amount, &record.Description, &record.Category, &record.PaymentMethod, &record.CreatedAt)
		if err != nil {
			http.Error(w, `{"error": "Error scanning records"}`, http.StatusInternalServerError)
			log.Println("Error scanning record:", err)
			return
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		http.Error(w, `{"error": "Error iterating over records"}`, http.StatusInternalServerError)
		log.Println("Error iterating over rows:", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(records)
}
