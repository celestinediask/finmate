package controllers

import (
	"encoding/json"
	"finmate/database"
	"log"
	"net/http"
	"os"

	razorpay "github.com/razorpay/razorpay-go"
)

func CreateOrder(w http.ResponseWriter, r *http.Request) {
	var requestData struct {
		Plan string `json:"plan"`
	}

	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	planName := requestData.Plan
	if planName == "" {
		http.Error(w, "Plan name is required", http.StatusBadRequest)
		return
	}

	amount, err := getPlanAmount(planName)
	if err != nil {
		log.Println("Error fetching plan amount:", err)
		http.Error(w, "Failed to fetch plan amount", http.StatusInternalServerError)
		return
	}

	client := razorpay.NewClient(os.Getenv("RAZORPAY_KEY"), os.Getenv("RAZORPAY_SECRET"))

	data := map[string]interface{}{
		"amount":   amount * 100, // Razorpay expects amount in paise
		"currency": "INR",
		"receipt":  "some_receipt_id",
	}

	body, err := client.Order.Create(data, nil)
	if err != nil {
		log.Println("Error creating Razorpay order:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	orderID, _ := body["id"].(string)
	amountFloat, _ := body["amount"].(float64)
	currency, _ := body["currency"].(string)
	receipt, _ := body["receipt"].(string)

	err = saveOrderToDB(orderID, amountFloat, currency, receipt)
	if err != nil {
		log.Println("Error saving order to database:", err)
		http.Error(w, "Failed to save order", http.StatusInternalServerError)
		return
	}

	response, err := json.Marshal(body)
	if err != nil {
		http.Error(w, "Failed to parse response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}

func saveOrderToDB(orderID string, amount float64, currency string, receipt string) error {
	db := database.DB
	_, err := db.Exec(`
        INSERT INTO orders (order_id, amount, currency, receipt) 
        VALUES ($1, $2, $3, $4)`,
		orderID, amount, currency, receipt)
	return err
}

func getPlanAmount(planName string) (int, error) {
	db := database.DB

	var amount int
	query := "SELECT price FROM plans WHERE name=$1"
	err := db.QueryRow(query, planName).Scan(&amount)
	if err != nil {
		return 0, err
	}
	return amount, nil
}
