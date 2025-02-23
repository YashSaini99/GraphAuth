package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// User represents a registered user.
type User struct {
	ID               primitive.ObjectID `bson:"_id,omitempty"`
	Username         string             `bson:"username"`
	Email            string             `bson:"email"`
	PatternHash      string             `bson:"pattern_hash"`
	OTPSecret        string             `bson:"otp_secret"`
	ResetToken       string             `bson:"reset_token,omitempty"`
	ResetTokenExpiry time.Time          `bson:"reset_token_expiry,omitempty"`
	FailedAttempts   int                `bson:"failed_attempts,omitempty"`
	LockUntil        time.Time          `bson:"lock_until,omitempty"`
}
