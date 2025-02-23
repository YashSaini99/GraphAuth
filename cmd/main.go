package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"graphauth/internal/auth"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

func init() {
	// Load environment variables from .env file.
	if err := godotenv.Load(); err != nil {
		log.Println("Warning: .env file not found")
	}
}

// writeJSONError is a helper that writes an error response in JSON.
func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func main() {
	// Create a context for initialization.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Initialize the authentication module.
	if err := auth.Init(ctx); err != nil {
		log.Fatalf("Initialization error: %v", err)
	}
	defer func() {
		if err := auth.Disconnect(ctx); err != nil {
			log.Printf("Error disconnecting from DB: %v", err)
		}
	}()

	// Create a new Gorilla Mux router.
	router := mux.NewRouter()

	// Define REST API endpoints.
	router.HandleFunc("/api/register", registerHandler).Methods("POST")
	router.HandleFunc("/api/login", loginHandler).Methods("POST")
	router.HandleFunc("/api/verify-otp", verifyOTPHandler).Methods("POST")
	router.HandleFunc("/api/forgot", forgotPasswordHandler).Methods("POST")
	router.HandleFunc("/api/reset", resetPasswordHandler).Methods("POST")

	// Serve static files from the "static" directory.
	fs := http.FileServer(http.Dir("./static"))
	router.PathPrefix("/").Handler(fs)

	// Wrap the router with logging middleware.
	loggedRouter := handlers.LoggingHandler(os.Stdout, router)

	// Determine the port.
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	addr := ":" + port

	// Create the HTTP server.
	srv := &http.Server{
		Handler:      loggedRouter,
		Addr:         addr,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start the server in a goroutine.
	go func() {
		log.Printf("Server running on http://localhost%s", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Wait for interrupt signals for graceful shutdown.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	// Graceful shutdown.
	ctxShutdown, cancelShutdown := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelShutdown()
	if err := srv.Shutdown(ctxShutdown); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}
	log.Println("Server exiting gracefully.")
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Pattern  string `json:"pattern"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	if req.Username == "" || req.Email == "" || req.Pattern == "" {
		writeJSONError(w, http.StatusBadRequest, "Missing fields")
		return
	}
	if err := auth.RegisterUser(req.Username, req.Email, req.Pattern); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Registration failed: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": fmt.Sprintf("Registration successful for %s (%s)", req.Username, req.Email),
	})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Pattern  string `json:"pattern"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	if req.Username == "" || req.Email == "" || req.Pattern == "" {
		writeJSONError(w, http.StatusBadRequest, "Missing fields")
		return
	}
	if err := auth.VerifyPattern(req.Username, req.Pattern); err != nil {
		writeJSONError(w, http.StatusUnauthorized, "Login failed: "+err.Error())
		return
	}
	userEmail, err := auth.GetUserEmail(req.Username)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Could not retrieve user email")
		return
	}
	if userEmail != req.Email {
		writeJSONError(w, http.StatusUnauthorized, "Email does not match our records")
		return
	}
	if err := auth.SendOTPEmail(req.Username); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Failed to send OTP: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": fmt.Sprintf("OTP sent to %s", userEmail),
	})
}

func verifyOTPHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		OTP      string `json:"otp"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	if req.Username == "" || req.OTP == "" {
		writeJSONError(w, http.StatusBadRequest, "Missing fields")
		return
	}
	if err := auth.VerifyOTP(req.Username, req.OTP); err != nil {
		// Return a custom JSON error message.
		writeJSONError(w, http.StatusUnauthorized, "OTP is wrong. Please provide the correct OTP.")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Login successful",
	})
}

func forgotPasswordHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	if req.Username == "" || req.Email == "" {
		writeJSONError(w, http.StatusBadRequest, "Missing fields")
		return
	}
	userEmail, err := auth.GetUserEmail(req.Username)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "User not found")
		return
	}
	if userEmail != req.Email {
		writeJSONError(w, http.StatusUnauthorized, "Email does not match records")
		return
	}
	if err := auth.ForgotPassword(req.Username); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Error: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": fmt.Sprintf("Sent a pass change link to %s", userEmail),
	})
}

func resetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username   string `json:"username"`
		Token      string `json:"token"`
		NewPattern string `json:"new_pattern"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	if req.Username == "" || req.Token == "" || req.NewPattern == "" {
		writeJSONError(w, http.StatusBadRequest, "Missing fields")
		return
	}
	if err := auth.ResetPassword(req.Username, req.Token, req.NewPattern); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Reset failed: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Password reset successful",
	})
}
