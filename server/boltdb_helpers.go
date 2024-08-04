package main

import (
	"fmt"
	"log"

	"go.etcd.io/bbolt"
)

func openDatabase(dbPath string) (*bbolt.DB, error) {
	var err error
	db, err = bbolt.Open(dbPath, 0600, nil)
	if err != nil {
		return nil, err
	}
	return db, nil
}

func createBucket(db *bbolt.DB, bucketName string) error {
	return db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		return err
	})
}

// Function to add an entry to the database
func addCredential(db *bbolt.DB, bucketName string, username string, password []byte) error {
	return db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketName))
		if bucket == nil {
			log.Printf("Bucket '%s' not found", bucketName)
			return fmt.Errorf("bucket not found")
		}
		return bucket.Put([]byte(username), password)
	})
}

// Function to retrieve a value based on a key
func getCredential(db *bbolt.DB, bucketName string, username string) ([]byte, error) {
	var password []byte
	err := db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketName))
		if bucket == nil {
			return fmt.Errorf("bucket not found")
		}
		password = bucket.Get([]byte(username))
		if password == nil {
			return fmt.Errorf("credential not found")
		}
		return nil
	})
	return password, err
}
