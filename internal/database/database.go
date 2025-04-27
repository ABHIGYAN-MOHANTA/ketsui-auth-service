package database

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "github.com/joho/godotenv/autoload"
	"github.com/markbates/goth"
)

// OAuthAccount represents a user account authenticated through OAuth
type OAuthAccount struct {
	ID                int64
	Provider          string
	Email             string
	Name              string
	FirstName         string
	LastName          string
	NickName          string
	Description       string
	UserID            string
	AvatarURL         string
	Location          string
	AccessToken       string
	AccessTokenSecret string
	RefreshToken      string
	ExpiresAt         time.Time
	IDToken           string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// Service represents a service that interacts with a database.
type Service interface {
	// Health returns a map of health status information.
	// The keys and values in the map are service-specific.
	Health() map[string]string

	// Close terminates the database connection.
	// It returns an error if the connection cannot be closed.
	Close() error
	
	// User account methods
	StoreOAuthAccount(user goth.User) (*OAuthAccount, error)
	GetOAuthAccountByID(userID string, provider string) (*OAuthAccount, error)
	GetOAuthAccountByEmail(email string) (*OAuthAccount, error)
}

type service struct {
	db *sql.DB
}

var (
	database   = os.Getenv("BLUEPRINT_DB_DATABASE")
	password   = os.Getenv("BLUEPRINT_DB_PASSWORD")
	username   = os.Getenv("BLUEPRINT_DB_USERNAME")
	port       = os.Getenv("BLUEPRINT_DB_PORT")
	host       = os.Getenv("BLUEPRINT_DB_HOST")
	schema     = os.Getenv("BLUEPRINT_DB_SCHEMA")
	dbInstance *service
)

func New() Service {
	// Reuse Connection
	if dbInstance != nil {
		return dbInstance
	}
	connStr := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable&search_path=%s", username, password, host, port, database, schema)
	db, err := sql.Open("pgx", connStr)
	if err != nil {
		log.Fatal(err)
	}
	dbInstance = &service{
		db: db,
	}
	return dbInstance
}

// Health checks the health of the database connection by pinging the database.
// It returns a map with keys indicating various health statistics.
func (s *service) Health() map[string]string {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	stats := make(map[string]string)

	// Ping the database
	err := s.db.PingContext(ctx)
	if err != nil {
		stats["status"] = "down"
		stats["error"] = fmt.Sprintf("db down: %v", err)
		log.Fatalf("db down: %v", err) // Log the error and terminate the program
		return stats
	}

	// Database is up, add more statistics
	stats["status"] = "up"
	stats["message"] = "It's healthy"

	// Get database stats (like open connections, in use, idle, etc.)
	dbStats := s.db.Stats()
	stats["open_connections"] = strconv.Itoa(dbStats.OpenConnections)
	stats["in_use"] = strconv.Itoa(dbStats.InUse)
	stats["idle"] = strconv.Itoa(dbStats.Idle)
	stats["wait_count"] = strconv.FormatInt(dbStats.WaitCount, 10)
	stats["wait_duration"] = dbStats.WaitDuration.String()
	stats["max_idle_closed"] = strconv.FormatInt(dbStats.MaxIdleClosed, 10)
	stats["max_lifetime_closed"] = strconv.FormatInt(dbStats.MaxLifetimeClosed, 10)

	// Evaluate stats to provide a health message
	if dbStats.OpenConnections > 40 { // Assuming 50 is the max for this example
		stats["message"] = "The database is experiencing heavy load."
	}

	if dbStats.WaitCount > 1000 {
		stats["message"] = "The database has a high number of wait events, indicating potential bottlenecks."
	}

	if dbStats.MaxIdleClosed > int64(dbStats.OpenConnections)/2 {
		stats["message"] = "Many idle connections are being closed, consider revising the connection pool settings."
	}

	if dbStats.MaxLifetimeClosed > int64(dbStats.OpenConnections)/2 {
		stats["message"] = "Many connections are being closed due to max lifetime, consider increasing max lifetime or revising the connection usage pattern."
	}

	return stats
}

// Close closes the database connection.
// It logs a message indicating the disconnection from the specific database.
// If the connection is successfully closed, it returns nil.
// If an error occurs while closing the connection, it returns the error.
func (s *service) Close() error {
	log.Printf("Disconnected from database: %s", database)
	return s.db.Close()
}

// StoreOAuthAccount stores or updates the OAuth account in the database
func (s *service) StoreOAuthAccount(user goth.User) (*OAuthAccount, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	// Check if user already exists
	var existingAccount OAuthAccount
	err := s.db.QueryRowContext(ctx, `
		SELECT id, user_id, provider, email, name, first_name, last_name, 
			   nickname, description, avatar_url, location, 
			   access_token, access_token_secret, refresh_token, expires_at, id_token, 
			   created_at, updated_at
		FROM oauth_accounts 
		WHERE user_id = $1 AND provider = $2
	`, user.UserID, user.Provider).Scan(
		&existingAccount.ID, &existingAccount.UserID, &existingAccount.Provider,
		&existingAccount.Email, &existingAccount.Name, &existingAccount.FirstName, &existingAccount.LastName,
		&existingAccount.NickName, &existingAccount.Description, &existingAccount.AvatarURL, &existingAccount.Location,
		&existingAccount.AccessToken, &existingAccount.AccessTokenSecret, &existingAccount.RefreshToken, 
		&existingAccount.ExpiresAt, &existingAccount.IDToken, &existingAccount.CreatedAt, &existingAccount.UpdatedAt,
	)
	
	if err != nil {
		if err == sql.ErrNoRows {
			// User doesn't exist, create a new one
			var newAccount OAuthAccount
			err = s.db.QueryRowContext(ctx, `
				INSERT INTO oauth_accounts (
					user_id, provider, email, name, first_name, last_name, 
					nickname, description, avatar_url, location, 
					access_token, access_token_secret, refresh_token, expires_at, id_token,
					created_at, updated_at
				) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, NOW(), NOW())
				RETURNING id, created_at, updated_at
			`, user.UserID, user.Provider, user.Email, user.Name, user.FirstName, user.LastName,
				user.NickName, user.Description, user.AvatarURL, user.Location,
				user.AccessToken, user.AccessTokenSecret, user.RefreshToken, user.ExpiresAt, user.IDToken,
			).Scan(&newAccount.ID, &newAccount.CreatedAt, &newAccount.UpdatedAt)
			
			if err != nil {
				return nil, fmt.Errorf("error creating oauth account: %w", err)
			}
			
			// Copy the user data to our account object
			newAccount.UserID = user.UserID
			newAccount.Provider = user.Provider
			newAccount.Email = user.Email
			newAccount.Name = user.Name
			newAccount.FirstName = user.FirstName
			newAccount.LastName = user.LastName
			newAccount.NickName = user.NickName
			newAccount.Description = user.Description
			newAccount.AvatarURL = user.AvatarURL
			newAccount.Location = user.Location
			newAccount.AccessToken = user.AccessToken
			newAccount.AccessTokenSecret = user.AccessTokenSecret
			newAccount.RefreshToken = user.RefreshToken
			newAccount.ExpiresAt = user.ExpiresAt
			newAccount.IDToken = user.IDToken
			
			return &newAccount, nil
		}
		
		return nil, fmt.Errorf("error checking for existing oauth account: %w", err)
	}
	
	// User exists, update their data
	_, err = s.db.ExecContext(ctx, `
		UPDATE oauth_accounts SET
			email = $1, name = $2, first_name = $3, last_name = $4,
			nickname = $5, description = $6, avatar_url = $7, location = $8,
			access_token = $9, access_token_secret = $10, refresh_token = $11,
			expires_at = $12, id_token = $13, updated_at = NOW()
		WHERE user_id = $14 AND provider = $15
	`, user.Email, user.Name, user.FirstName, user.LastName,
	   user.NickName, user.Description, user.AvatarURL, user.Location,
	   user.AccessToken, user.AccessTokenSecret, user.RefreshToken,
	   user.ExpiresAt, user.IDToken, user.UserID, user.Provider)
	
	if err != nil {
		return nil, fmt.Errorf("error updating oauth account: %w", err)
	}
	
	// Get the updated record to return
	var updatedAccount OAuthAccount
	err = s.db.QueryRowContext(ctx, `
		SELECT id, user_id, provider, email, name, first_name, last_name, 
			   nickname, description, avatar_url, location, 
			   access_token, access_token_secret, refresh_token, expires_at, id_token, 
			   created_at, updated_at
		FROM oauth_accounts 
		WHERE user_id = $1 AND provider = $2
	`, user.UserID, user.Provider).Scan(
		&updatedAccount.ID, &updatedAccount.UserID, &updatedAccount.Provider,
		&updatedAccount.Email, &updatedAccount.Name, &updatedAccount.FirstName, &updatedAccount.LastName,
		&updatedAccount.NickName, &updatedAccount.Description, &updatedAccount.AvatarURL, &updatedAccount.Location,
		&updatedAccount.AccessToken, &updatedAccount.AccessTokenSecret, &updatedAccount.RefreshToken, 
		&updatedAccount.ExpiresAt, &updatedAccount.IDToken, &updatedAccount.CreatedAt, &updatedAccount.UpdatedAt,
	)
	
	if err != nil {
		return nil, fmt.Errorf("error retrieving updated oauth account: %w", err)
	}
	
	return &updatedAccount, nil
}

// GetOAuthAccountByID retrieves an OAuth account by its user ID and provider
func (s *service) GetOAuthAccountByID(userID string, provider string) (*OAuthAccount, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	var account OAuthAccount
	err := s.db.QueryRowContext(ctx, `
		SELECT id, user_id, provider, email, name, first_name, last_name, 
			   nickname, description, avatar_url, location, 
			   access_token, access_token_secret, refresh_token, expires_at, id_token, 
			   created_at, updated_at
		FROM oauth_accounts 
		WHERE user_id = $1 AND provider = $2
	`, userID, provider).Scan(
		&account.ID, &account.UserID, &account.Provider,
		&account.Email, &account.Name, &account.FirstName, &account.LastName,
		&account.NickName, &account.Description, &account.AvatarURL, &account.Location,
		&account.AccessToken, &account.AccessTokenSecret, &account.RefreshToken, 
		&account.ExpiresAt, &account.IDToken, &account.CreatedAt, &account.UpdatedAt,
	)
	
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Return nil, nil to indicate not found
		}
		return nil, fmt.Errorf("error getting oauth account by user ID: %w", err)
	}
	
	return &account, nil
}

// GetOAuthAccountByEmail retrieves an OAuth account by email address
func (s *service) GetOAuthAccountByEmail(email string) (*OAuthAccount, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	var account OAuthAccount
	err := s.db.QueryRowContext(ctx, `
		SELECT id, user_id, provider, email, name, first_name, last_name, 
			   nickname, description, avatar_url, location, 
			   access_token, access_token_secret, refresh_token, expires_at, id_token, 
			   created_at, updated_at
		FROM oauth_accounts 
		WHERE email = $1
		ORDER BY updated_at DESC
		LIMIT 1
	`, email).Scan(
		&account.ID, &account.UserID, &account.Provider,
		&account.Email, &account.Name, &account.FirstName, &account.LastName,
		&account.NickName, &account.Description, &account.AvatarURL, &account.Location,
		&account.AccessToken, &account.AccessTokenSecret, &account.RefreshToken, 
		&account.ExpiresAt, &account.IDToken, &account.CreatedAt, &account.UpdatedAt,
	)
	
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Return nil, nil to indicate not found
		}
		return nil, fmt.Errorf("error getting oauth account by email: %w", err)
	}
	
	return &account, nil
}
