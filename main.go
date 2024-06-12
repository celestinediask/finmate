package main

import (
	"finmate/config"
	"finmate/controllers"
	"finmate/database"
	"fmt"

	"github.com/gin-gonic/gin"
)

func init() {
	config.LoadEnv()
	database.ConnectDB()
	database.SyncDB()
}

// sort time
// sort amount
// sort by date
// filter by category

func main() {

	fmt.Println("hello how")

	r := gin.Default()

	// public routes
	r.POST("/signup", controllers.Signup)
	r.POST("/send-email-otp", controllers.SendOTPEmail)
	r.POST("/verify-email", controllers.VerifyEmail)
	r.POST("/login", controllers.Login)
	//r.POST("/logout", controllers.Logout)

	// home
	userRoutes := r.Group("/", controllers.UserAuthMiddleware())
	{
		userRoutes.GET("/validate", controllers.Validate)
		userRoutes.GET("/profile", controllers.Profile)
		userRoutes.POST("/add-record", controllers.AddRecord)
		userRoutes.GET("/list-records", controllers.ListRecords)
		userRoutes.PUT("/edit-record/:id", controllers.EditRecord)
		userRoutes.DELETE("/delete-record/:id", controllers.DeleteRecord)

		userRoutes.GET("/get-record/:id", controllers.GetRecordByID)
		userRoutes.PATCH("/patch-record/:id", controllers.PatchRecord)
		userRoutes.GET("/search-records", controllers.SearchRecords)
		//userRoutes.GET("/count-records", controllers.CountRecords)
	}

	r.Run(":8080")
}
