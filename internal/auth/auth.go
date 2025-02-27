package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"net/smtp"
	"os"
	"time"

	"graphauth/internal/database"
	"graphauth/internal/models"
	"graphauth/internal/util"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

var (
	mongoClient *mongo.Client
	userCol     *mongo.Collection
)

// Init establishes a connection to MongoDB and initializes the users collection.
func Init(ctx context.Context) error {
	client, err := database.ConnectMongoDB(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to MongoDB: %w", err)
	}
	mongoClient = client
	userCol = database.GetUserCollection(client)
	return nil
}

// Disconnect disconnects from MongoDB.
func Disconnect(ctx context.Context) error {
	if mongoClient == nil {
		return nil
	}
	if err := mongoClient.Disconnect(ctx); err != nil {
		return fmt.Errorf("failed to disconnect from MongoDB: %w", err)
	}
	return nil
}

// hashPattern hashes the provided pattern using bcrypt.
func hashPattern(pattern string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(pattern), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to generate bcrypt hash: %w", err)
	}
	return string(hash), nil
}

// comparePatternHash compares the provided pattern with the stored bcrypt hash.
func comparePatternHash(pattern, hash string) error {
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(pattern)); err != nil {
		return err
	}
	return nil
}

// generateResetToken creates a secure random token for password reset.
func generateResetToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// GetUserEmail retrieves the user's email by username.
func GetUserEmail(username string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user models.User
	if err := userCol.FindOne(ctx, bson.M{"username": username}).Decode(&user); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return "", errors.New("user not found")
		}
		return "", fmt.Errorf("error retrieving user: %w", err)
	}
	return user.Email, nil
}

// RegisterUser registers a new user by validating email, checking duplicates,
// hashing the pattern with bcrypt, generating an OTP secret, and storing the record.
func RegisterUser(username, email, pattern string) error {
	if !util.ValidateEmail(email) {
		return errors.New("invalid email format")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var existing models.User
	if err := userCol.FindOne(ctx, bson.M{"username": username}).Decode(&existing); err == nil {
		return errors.New("user already exists")
	} else if err != mongo.ErrNoDocuments {
		return fmt.Errorf("error checking existing user: %w", err)
	}

	hashedPattern, err := hashPattern(pattern)
	if err != nil {
		return fmt.Errorf("error hashing pattern: %w", err)
	}

	otpKey, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "GraphAuth",
		AccountName: username,
	})
	if err != nil {
		return fmt.Errorf("error generating OTP secret: %w", err)
	}

	newUser := models.User{
		Username:       username,
		Email:          email,
		PatternHash:    hashedPattern,
		OTPSecret:      otpKey.Secret(),
		FailedAttempts: 0,
	}

	if _, err := userCol.InsertOne(ctx, newUser); err != nil {
		return fmt.Errorf("error inserting user: %w", err)
	}
	log.Printf("User %s registered successfully.", username)
	return nil
}

// VerifyPattern checks if the provided pattern matches the stored bcrypt hash.
// On an incorrect pattern, it increments the failed attempts counter.
// After 5 failed attempts, it locks the account for 1 minute and sends an alert email.
func VerifyPattern(username, pattern string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user models.User
	if err := userCol.FindOne(ctx, bson.M{"username": username}).Decode(&user); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return errors.New("user not found")
		}
		return fmt.Errorf("error retrieving user: %w", err)
	}

	// Check if account is locked.
	if !user.LockUntil.IsZero() && time.Now().Before(user.LockUntil) {
		return fmt.Errorf("account is temporarily locked until %s", user.LockUntil.Format(time.RFC1123))
	}

	// Compare pattern hash using bcrypt.
	if err := comparePatternHash(pattern, user.PatternHash); err != nil {
		newAttempts := user.FailedAttempts + 1
		update := bson.M{"$set": bson.M{"failed_attempts": newAttempts}}
		if newAttempts >= 5 {
			lockTime := time.Now().Add(1 * time.Minute)
			update["$set"].(bson.M)["lock_until"] = lockTime
			go func() {
				if err := SendAlertEmail(username, lockTime); err != nil {
					log.Printf("Failed to send alert email: %v", err)
				}
			}()
		}
		if _, err := userCol.UpdateOne(ctx, bson.M{"username": username}, update); err != nil {
			log.Printf("Error updating failed attempts: %v", err)
		}
		return errors.New("incorrect pattern")
	}

	// If pattern is correct, reset failed attempts and clear lock.
	update := bson.M{"$set": bson.M{"failed_attempts": 0}, "$unset": bson.M{"lock_until": ""}}
	if _, err := userCol.UpdateOne(ctx, bson.M{"username": username}, update); err != nil {
		log.Printf("Error resetting failed attempts: %v", err)
	}
	return nil
}

// VerifyOTP validates the OTP using the user's stored OTP secret with a 5-minute period.
func VerifyOTP(username, code string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user models.User
	if err := userCol.FindOne(ctx, bson.M{"username": username}).Decode(&user); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return errors.New("user not found")
		}
		return fmt.Errorf("error retrieving user: %w", err)
	}

	opts := totp.ValidateOpts{
		Period:    300, // 5 minutes validity
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	}
	valid, err := totp.ValidateCustom(code, user.OTPSecret, time.Now(), opts)
	if err != nil {
		return fmt.Errorf("error validating OTP: %w", err)
	}
	if !valid {
		return errors.New("invalid OTP")
	}
	return nil
}

// ForgotPassword handles a forgot password request by generating a reset token,
// storing it in the user's record with an expiry, and sending a reset email.
func ForgotPassword(username string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user models.User
	if err := userCol.FindOne(ctx, bson.M{"username": username}).Decode(&user); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return errors.New("user not found")
		}
		return fmt.Errorf("error retrieving user: %w", err)
	}

	token, err := generateResetToken()
	if err != nil {
		return fmt.Errorf("failed to generate reset token: %w", err)
	}
	expiry := time.Now().Add(1 * time.Hour)

	update := bson.M{
		"$set": bson.M{
			"reset_token":        token,
			"reset_token_expiry": expiry,
		},
	}
	if _, err := userCol.UpdateOne(ctx, bson.M{"username": username}, update); err != nil {
		return fmt.Errorf("failed to update reset token: %w", err)
	}

	subject := "GraphAuth Password Reset Request"
	resetLink := fmt.Sprintf("https://yourdomain.com/reset-password?username=%s&token=%s", username, token)
	body := fmt.Sprintf("Dear %s,\n\nPlease use the following link to reset your graphical pattern:\n%s\n\nThis link will expire in 1 hour.\n\nRegards,\nGraphAuth Team", username, resetLink)
	if err := sendEmail(user.Email, subject, body); err != nil {
		return fmt.Errorf("failed to send reset email: %w", err)
	}
	log.Printf("Password reset email sent to %s", user.Email)
	return nil
}

// ResetPassword allows a user to reset their graphical pattern given a valid token.
func ResetPassword(username, token, newPattern string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user models.User
	if err := userCol.FindOne(ctx, bson.M{"username": username}).Decode(&user); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return errors.New("user not found")
		}
		return fmt.Errorf("error retrieving user: %w", err)
	}
	if user.ResetToken != token || time.Now().After(user.ResetTokenExpiry) {
		return errors.New("invalid or expired reset token")
	}

	hashedPattern, err := hashPattern(newPattern)
	if err != nil {
		return fmt.Errorf("failed to hash new pattern: %w", err)
	}

	update := bson.M{
		"$set": bson.M{"pattern_hash": hashedPattern},
		"$unset": bson.M{
			"reset_token":        "",
			"reset_token_expiry": "",
		},
	}
	if _, err := userCol.UpdateOne(ctx, bson.M{"username": username}, update); err != nil {
		return fmt.Errorf("failed to update new pattern: %w", err)
	}
	log.Printf("Password for user %s reset successfully.", username)
	return nil
}

// sendEmail sends an email using SMTP with credentials from environment variables.
func sendEmail(recipient, subject, body string) error {
	smtpServer := os.Getenv("SMTP_SERVER")
	smtpUser := os.Getenv("SMTP_USER")
	smtpPassword := os.Getenv("SMTP_PASSWORD")

	if smtpServer == "" || smtpUser == "" || smtpPassword == "" {
		return errors.New("SMTP environment variables are not set")
	}

	host, port, err := net.SplitHostPort(smtpServer)
	if err != nil {
		return fmt.Errorf("invalid SMTP_SERVER format (expected host:port): %w", err)
	}

	auth := smtp.PlainAuth("", smtpUser, smtpPassword, host)

	msg := []byte("To: " + recipient + "\r\n" +
		"Subject: " + subject + "\r\n\r\n" +
		body + "\r\n")

	if err := smtp.SendMail(smtpServer, auth, smtpUser, []string{recipient}, msg); err != nil {
		return fmt.Errorf("failed to send email via %s:%s - %w", host, port, err)
	}
	return nil
}

// SendOTPEmail retrieves the user by username, generates an OTP valid for 5 minutes, and sends it to the user's email.
func SendOTPEmail(username string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user models.User
	if err := userCol.FindOne(ctx, bson.M{"username": username}).Decode(&user); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return errors.New("user not found")
		}
		return fmt.Errorf("error retrieving user: %w", err)
	}

	opts := totp.ValidateOpts{
		Period:    300, // 5 minutes validity
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	}
	code, err := totp.GenerateCodeCustom(user.OTPSecret, time.Now(), opts)
	if err != nil {
		return fmt.Errorf("failed to generate OTP code: %w", err)
	}

	subject := "Your OTP Code"
	body := fmt.Sprintf("Dear %s,\n\nYour OTP code is: %s\nIt is valid for 5 minutes.\n\nRegards,\nGraphAuth Team", username, code)
	if err := sendEmail(user.Email, subject, body); err != nil {
		return fmt.Errorf("failed to send OTP email: %w", err)
	}
	log.Printf("OTP email sent to %s", user.Email)
	return nil
}

// SendAlertEmail sends an alert email to the user when multiple failed login attempts occur.
func SendAlertEmail(username string, lockTime time.Time) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user models.User
	if err := userCol.FindOne(ctx, bson.M{"username": username}).Decode(&user); err != nil {
		return fmt.Errorf("error retrieving user for alert: %w", err)
	}
	subject := "Alert: Suspicious Login Attempts Detected"
	body := fmt.Sprintf("Dear %s,\n\nMultiple failed login attempts have been detected on your account. Your account has been temporarily locked until %s for security reasons.\n\nIf this wasn't you, please secure your account immediately.\n\nRegards,\nGraphAuth Team", username, lockTime.Format(time.RFC1123))
	if err := sendEmail(user.Email, subject, body); err != nil {
		return fmt.Errorf("failed to send alert email: %w", err)
	}
	return nil
}
