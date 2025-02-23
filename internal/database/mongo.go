package database

import (
	"context"
	"log"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// GetMongoURI returns the MongoDB URI from an environment variable or a default value.
func GetMongoURI() string {
	uri := os.Getenv("MONGO_URI")
	if uri == "" {
		uri = "mongodb://localhost:27017"
	}
	return uri
}

// ConnectMongoDB establishes a connection to MongoDB and returns the client.
func ConnectMongoDB(ctx context.Context) (*mongo.Client, error) {
	clientOptions := options.Client().ApplyURI(GetMongoURI())
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return nil, err
	}
	// Ping the database to verify connection.
	ctxPing, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctxPing, nil); err != nil {
		return nil, err
	}
	log.Println("Connected to MongoDB")
	return client, nil
}

// GetUserCollection returns the MongoDB collection for users.
func GetUserCollection(client *mongo.Client) *mongo.Collection {
	dbName := os.Getenv("MONGO_DB")
	if dbName == "" {
		dbName = "graphauth"
	}
	return client.Database(dbName).Collection("users")
}
