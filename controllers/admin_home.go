package controllers

import (
	"encoding/json"
	"finmate/database"
	"finmate/models"
	"net/http"
	"strconv"

	"github.com/go-chi/chi"
)

func ValidateAdmin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "I'm logged in as admin"})
}

func AddSubscriptionPlan(w http.ResponseWriter, r *http.Request) {
	var plan models.SubscriptionPlan
	db := database.DB
	if err := json.NewDecoder(r.Body).Decode(&plan); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	query := `INSERT INTO plans (name, description, price) VALUES ($1, $2, $3)`
	_, err := db.Exec(query, plan.Name, plan.Description, plan.Price)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("Plan added successfully"))
}

func DeletePlan(w http.ResponseWriter, r *http.Request) {
	db := database.DB
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid plan ID", http.StatusBadRequest)
		return
	}

	query := `DELETE FROM plans WHERE id = $1`
	result, err := db.Exec(query, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if rowsAffected == 0 {
		http.Error(w, "No plan found with the given ID", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Plan deleted successfully"))
}
