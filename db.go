package main

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

const schema = `
CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    access_key TEXT UNIQUE NOT NULL,
    secret_key TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS buckets (
    id SERIAL PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_buckets_account_id ON buckets(account_id);
CREATE INDEX IF NOT EXISTS idx_accounts_access_key ON accounts(access_key);
`

// DB wraps a sql.DB with application-specific methods.
type DB struct {
	*sql.DB
}

func initDB(databaseURL string) (*DB, error) {
	conn, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err := conn.Ping(); err != nil {
		return nil, fmt.Errorf("ping database: %w", err)
	}
	if _, err := conn.Exec(schema); err != nil {
		return nil, fmt.Errorf("create schema: %w", err)
	}
	return &DB{conn}, nil
}

// Account represents a registered account.
type Account struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
}

// CreateAccount inserts a new account.
func (db *DB) CreateAccount(id, name, accessKey, secretKey string) error {
	_, err := db.Exec(
		"INSERT INTO accounts (id, name, access_key, secret_key) VALUES ($1, $2, $3, $4)",
		id, name, accessKey, secretKey,
	)
	return err
}

// GetAccount retrieves an account by ID.
func (db *DB) GetAccount(id string) (*Account, error) {
	var a Account
	err := db.QueryRow(
		"SELECT id, name, access_key, secret_key FROM accounts WHERE id = $1", id,
	).Scan(&a.ID, &a.Name, &a.AccessKey, &a.SecretKey)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &a, err
}

// GetAccountByAccessKey retrieves an account by access key.
func (db *DB) GetAccountByAccessKey(accessKey string) (*Account, error) {
	var a Account
	err := db.QueryRow(
		"SELECT id, name, access_key, secret_key FROM accounts WHERE access_key = $1", accessKey,
	).Scan(&a.ID, &a.Name, &a.AccessKey, &a.SecretKey)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &a, err
}

// DeleteAccount removes an account (cascades to buckets).
func (db *DB) DeleteAccount(id string) error {
	result, err := db.Exec("DELETE FROM accounts WHERE id = $1", id)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("account not found: %s", id)
	}
	return nil
}

// CreateBucket records a bucket-account mapping.
func (db *DB) CreateBucket(name, accountID string) error {
	_, err := db.Exec(
		"INSERT INTO buckets (name, account_id) VALUES ($1, $2)",
		name, accountID,
	)
	return err
}

// DeleteBucket removes a bucket mapping.
func (db *DB) DeleteBucket(name string) error {
	result, err := db.Exec("DELETE FROM buckets WHERE name = $1", name)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("bucket not found: %s", name)
	}
	return nil
}

// GetBucketAccount returns the account ID that owns a bucket.
func (db *DB) GetBucketAccount(name string) (string, error) {
	var accountID string
	err := db.QueryRow(
		"SELECT account_id FROM buckets WHERE name = $1", name,
	).Scan(&accountID)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return accountID, err
}

// ListBucketsByAccount returns all bucket names for an account.
func (db *DB) ListBucketsByAccount(accountID string) ([]string, error) {
	rows, err := db.Query(
		"SELECT name FROM buckets WHERE account_id = $1", accountID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}
