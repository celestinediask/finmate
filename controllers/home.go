package controllers

import (
	"finmate/database"
	"finmate/models"
	"net/http"

	"github.com/gin-gonic/gin"
)

func RedirectHome(c *gin.Context) {
	c.Redirect(http.StatusFound, "/home")
}

func Profile(c *gin.Context) {
	// Retrieve the email from the context
	username, _ := c.Get("username")
	email, _ := c.Get("email")

	// Pass the email to the template
	c.JSON(http.StatusOK, gin.H{"Username": username, "Email": email})
}

func AddRecord(c *gin.Context) {
	var record models.Record
	if err := c.BindJSON(&record); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	database.DB.Create(&record)
	c.JSON(http.StatusCreated, record)
}

func ListRecords(c *gin.Context) {
	var records []models.Record
	database.DB.Find(&records)
	c.JSON(http.StatusOK, records)
}

func EditRecord(c *gin.Context) {
	id := c.Param("id")
	var record models.Record
	if err := database.DB.Where("id = ?", id).First(&record).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Record not found"})
		return
	}
	if err := c.BindJSON(&record); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	database.DB.Save(&record)
	c.JSON(http.StatusOK, record)
}

func DeleteRecord(c *gin.Context) {
	id := c.Param("id")
	var record models.Record
	if err := database.DB.Where("id = ?", id).First(&record).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Record not found"})
		return
	}
	database.DB.Delete(&record)
	c.JSON(http.StatusOK, gin.H{"message": "Record deleted successfully"})
}

func GetRecordByID(c *gin.Context) {
	id := c.Param("id")
	var record models.Record
	if err := database.DB.Where("id = ?", id).First(&record).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Record not found"})
		return
	}
	c.JSON(http.StatusOK, record)
}

func PatchRecord(c *gin.Context) {
	id := c.Param("id")
	var record models.Record
	if err := database.DB.Where("id = ?", id).First(&record).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Record not found"})
		return
	}
	if err := c.ShouldBindJSON(&record); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	database.DB.Model(&record).Updates(record)
	c.JSON(http.StatusOK, record)
}

func SearchRecords(c *gin.Context) {
	var records []models.Record
	query := c.Request.URL.Query()
	db := database.DB

	for key, value := range query {
		db = db.Where(key+" = ?", value[0])
	}

	if err := db.Find(&records).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, records)
}

// func CountRecords(c *gin.Context) {
// 	var count int64
// 	if err := database.DB.Model(&models.Record).Count(&count).Error; err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
// 		return
// 	}
// 	c.JSON(http.StatusOK, gin.H{"count": count})
// }
