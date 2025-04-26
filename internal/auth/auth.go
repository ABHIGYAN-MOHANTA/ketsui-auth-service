package auth

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/google"
)

const (
	key = "authgoogleketsui02"
	MaxAge = 60 * 60 * 24 * 30 // 30 days
	IsProd = false
)

func NewAuth() {
	log.Println("Initializing authentication system...")
	
	// We'll be using gothic's session name: "_gothic_session"
	log.Printf("Using Gothic's default session name: %s", gothic.SessionName)
	
	err := godotenv.Load()
	if err != nil {
		log.Printf("Warning: Error loading .env file: %v", err)
		log.Println("Continuing with environment variables that may be set elsewhere")
	}

	googleClientID := os.Getenv("GOOGLE_CLIENT_ID")
	googleClientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
	
	if googleClientID == "" || googleClientSecret == "" {
		log.Println("WARNING: Google OAuth credentials missing or empty!")
		log.Printf("GOOGLE_CLIENT_ID present: %v", googleClientID != "")
		log.Printf("GOOGLE_CLIENT_SECRET present: %v", googleClientSecret != "")
	} else {
		log.Println("Google OAuth credentials loaded successfully")
	}

	// Create a more secure key
	secret := []byte(key)
	store := sessions.NewCookieStore(secret)
	store.MaxAge(MaxAge)

	store.Options.Path = "/"
	store.Options.HttpOnly = true
	store.Options.Secure = IsProd
	// Important: Allow session to be saved on the client side
	store.Options.SameSite = http.SameSiteLaxMode
	
	log.Printf("Cookie settings - Path: %s, HttpOnly: %v, Secure: %v, SameSite: %v", 
		store.Options.Path, store.Options.HttpOnly, store.Options.Secure, store.Options.SameSite)

	// Configure gothic to use the session store
	gothic.Store = store
	
	// Set Gothic to use GET for the provider parameter instead of context
	gothic.GetProviderName = func(req *http.Request) (string, error) {
		provider := chi.URLParam(req, "provider")
		log.Printf("GetProviderName called, URL: %s, found provider: %s", req.URL.Path, provider)
		if provider == "" {
			return "", fmt.Errorf("provider not found")
		}
		return provider, nil
	}
	
	callbackURL := "http://localhost:8080/auth/google/callback"
	log.Printf("Setting up Google provider with callback URL: %s", callbackURL)
	
	goth.UseProviders(
		google.New(googleClientID, googleClientSecret, callbackURL),
	)
	
	log.Println("Auth initialization complete")
}

