package models

type OrderRequest struct {
	Amount   int    `json:"amount"`
	Currency string `json:"currency"`
	Receipt  string `json:"receipt"`
}

type OrderResponse struct {
	OrderID string `json:"order_id"`
}
