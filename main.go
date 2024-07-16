package main

import (
	"finmate/config"
	"finmate/controllers"
	"finmate/database"
	"finmate/middlewares"
	"finmate/utils"

	"fmt"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
)

func init() {
	config.LoadEnv()
	//database.CreateDatabase()
	database.ConnectDB()
	database.MigrateTable()
}

/*
finish payment integration and admin side
Integrate online payment method(Razorpay or Paypal).
Coupon Management (Apply Coupon, Remove Coupon)
Admin side :
Offer module(Product offer, Category offer, Referral offer).
Sales report(Daily, Weekly, Yearly, Custom date)
Generate sales report ,Should be able to filter based on
Custom date range ,1 Day / week / month ,
Show  discount and coupons deduction in sales report
Overall sales count  ,Overall order amount ,
Overall discount,Report download (Pdf, Excel)""
Correct Jwt token validation
*/

func main() {

	r := chi.NewRouter()

	r.Use(middleware.Logger)

	// auth routes
	r.Post("/signup", controllers.Signup)
	r.Post("/send-email-otp", utils.SendOTPEmail)
	r.Post("/verify-email", controllers.VerifyEmail)
	r.Post("/login", controllers.Login)
	//r.Post("/logout", controllers.Logout)

	// user routes
	userRoutes := chi.NewRouter()
	r.Mount("/user", userRoutes)
	userRoutes.Use(middlewares.UserAuthMiddleware)
	userRoutes.Get("/validate", controllers.ValidateUser)
	userRoutes.Get("/profile", controllers.Profile)
	userRoutes.Post("/add-record", controllers.AddRecord)
	userRoutes.Get("/list-records", controllers.ListRecords)
	userRoutes.Put("/edit-record/{id}", controllers.EditRecord)
	userRoutes.Delete("/delete-record/{id}", controllers.DeleteRecord)
	userRoutes.Get("/get-record/{id}", controllers.GetRecordByID)
	userRoutes.Get("/search-records", controllers.SearchRecords)
	userRoutes.Get("/count-records", controllers.CountRecords)
	userRoutes.Get("/sort-records", controllers.SortRecords)
	userRoutes.Get("/list-plans", controllers.ListPlans)
	r.Post("/create-order", controllers.CreateOrder)

	// admin routes
	adminRoutes := chi.NewRouter()
	r.Mount("/admin", adminRoutes)
	adminRoutes.Use(middlewares.AdminAuthMiddleware)
	adminRoutes.Get("/validate", controllers.ValidateAdmin)
	adminRoutes.Post("/add-plan", controllers.AddSubscriptionPlan)
	adminRoutes.Delete("/delete-plan/{id}", controllers.DeletePlan)
	//adminRoutes.Put("/edit-plan/{id}", controllers.EditPlan)
	//adminRoutes.Get("/list-plans", controllers.ListPlans)

	fmt.Println("Server started on :8080")
	http.ListenAndServe(":8080", r)

}
