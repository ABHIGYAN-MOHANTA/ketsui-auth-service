package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
)

// JWT secret key - in production, this should be stored securely
const (
	jwtSecret = "ketsui-jwt-secret-key" // change this in production!
	jwtExpiry = 24 * time.Hour
)

// UserClaims represents the JWT claims
type UserClaims struct {
	UserID    string `json:"user_id"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	Provider  string `json:"provider"`
	jwt.RegisteredClaims
}

func (s *Server) RegisterRoutes() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Logger)

	// Add middleware to handle trailing slashes
	r.Use(middleware.RedirectSlashes)

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"https://*", "http://*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	r.Get("/", s.HelloWorldHandler)

	r.Get("/health", s.healthHandler)

	// Auth routes with explicit logging when they're registered
	log.Println("Registering auth routes...")
	
	// Define auth routes with explicit matching for both with and without trailing slash
	r.Get("/auth/{provider}", s.beginAuthHandler)
	r.Get("/auth/{provider}/", s.beginAuthHandler) // Explicitly handle trailing slash
	r.Get("/auth/{provider}/callback", s.getAuthCallback)
	r.Get("/auth/{provider}/callback/", s.getAuthCallback) // Explicitly handle trailing slash
	log.Printf("Registered auth routes with and without trailing slashes")
	
	// Add a route to check authentication status
	r.Get("/auth/status", s.authStatusHandler)
	
	// Protected routes that require authentication
	r.Group(func(r chi.Router) {
		r.Use(s.AuthMiddleware)
		
		// Standard protected route
		r.Get("/protected", s.protectedHandler)
		
		// User profile route
		r.Get("/user/profile", s.getUserProfileHandler)
		
		// OAuth user data route
		r.Get("/oauth/user", s.getOAuthUserHandler)
	})
	
	r.Get("/logout/{provider}", s.logoutHandler)
	r.Get("/logout/{provider}/", s.logoutHandler) // Explicitly handle trailing slash

	return r
}

func (s *Server) HelloWorldHandler(w http.ResponseWriter, r *http.Request) {
	resp := make(map[string]string)
	resp["message"] = "Hello World"

	jsonResp, err := json.Marshal(resp)
	if err != nil {
		log.Fatalf("error handling JSON marshal. Err: %v", err)
	}

	_, _ = w.Write(jsonResp)
}

func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	jsonResp, _ := json.Marshal(s.db.Health())
	_, _ = w.Write(jsonResp)
}

func (s *Server) getAuthCallback(w http.ResponseWriter, r *http.Request) {
	log.Printf("Auth callback received: %s %s", r.Method, r.URL.Path)
	
	// Get the provider from the URL
	provider := chi.URLParam(r, "provider")
	log.Printf("Auth callback for provider: %s", provider)
	
	// Update the context properly
	r = r.WithContext(context.WithValue(r.Context(), "provider", provider))

	// Try to complete the auth process
	user, err := gothic.CompleteUserAuth(w, r)
	if err != nil {
		log.Printf("Auth error: %v", err)
		http.Error(w, "Failed to complete user auth", http.StatusInternalServerError)
		return
	}

	log.Printf("User authenticated successfully: %s (%s)", user.Name, user.Email)
	
	// Store the user in the database
	oauthAccount, err := s.db.StoreOAuthAccount(user)
	if err != nil {
		log.Printf("Error storing OAuth account: %v", err)
		// Continue even if there's an error storing the account
	} else {
		log.Printf("OAuth account stored/updated successfully. ID: %d", oauthAccount.ID)
	}
	
	// Create JWT token
	token, err := createJWTToken(user, provider)
	if err != nil {
		log.Printf("Error creating JWT: %v", err)
		http.Error(w, "Authentication server error", http.StatusInternalServerError)
		return
	}
	
	// Redirect to frontend with JWT as query parameter
	redirectURL := fmt.Sprintf("http://localhost:3000?token=%s", token)
	log.Printf("Redirecting to: %s", "http://localhost:3000 with token")
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (s *Server) beginAuthHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received auth request: %s %s", r.Method, r.URL.Path)
	
	// Get the provider from the URL
	provider := chi.URLParam(r, "provider")
	log.Printf("Auth provider from URL parameter: %s", provider)
	
	// Add provider to context for gothic
	r = r.WithContext(context.WithValue(r.Context(), "provider", provider))
	
	// Log all existing cookies for debugging
	cookies := r.Cookies()
	log.Printf("Found %d cookies in the request", len(cookies))
	for _, cookie := range cookies {
		log.Printf("Cookie: %s=%s", cookie.Name, cookie.Value)
	}
	
	// Ensure the session is created and has a provider value
	// This will be saved to a cookie named "_gothic_session"
	session, _ := gothic.Store.Get(r, gothic.SessionName)
	session.Values["provider"] = provider
	// Important: Set other session parameters
	if err := session.Save(r, w); err != nil {
		log.Printf("Error saving session: %v", err)
	} else {
		log.Printf("Session saved successfully with provider: %s", provider)
	}
	
	// Attempt to complete auth first (user might already be authenticated)
	if user, err := gothic.CompleteUserAuth(w, r); err == nil {
		log.Printf("User already authenticated: %v", user)
		// User already authenticated
		jsonResp, _ := json.Marshal(user)
		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonResp)
		return
	} else {
		log.Printf("User not yet authenticated: %v", err)
	}

	log.Printf("Beginning auth flow for provider: %s", provider)
	
	// If not authenticated yet, begin the auth flow
	gothic.BeginAuthHandler(w, r)
}

func (s *Server) logoutHandler(w http.ResponseWriter, r *http.Request) {
	err := gothic.Logout(w, r)
	if err != nil {
		http.Error(w, "Failed to logout", http.StatusInternalServerError)
		return
	}
	// Redirect after logout
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

// Create JWT token from user data
func createJWTToken(user goth.User, provider string) (string, error) {
	expiryTime := time.Now().Add(jwtExpiry)
	
	claims := UserClaims{
		UserID:    user.UserID,
		Email:     user.Email,
		Name:      user.Name,
		Provider:  provider,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiryTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "ketsui-auth-service",
			Subject:   user.UserID,
		},
	}
	
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		return "", err
	}
	
	return tokenString, nil
}

// AuthMiddleware checks if a user is authenticated via JWT
func (s *Server) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("Checking JWT authentication")
		
		// Get the token from the Authorization header
		// Format: Bearer {token}
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			log.Println("No Authorization header found")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		
		// Check if the Authorization header has the correct format
		if len(authHeader) <= 7 || authHeader[:7] != "Bearer " {
			log.Println("Invalid Authorization format")
			http.Error(w, "Invalid Authorization format", http.StatusUnauthorized)
			return
		}
		
		// Extract the token
		tokenString := authHeader[7:]
		
		// Parse and validate the token
		token, err := jwt.ParseWithClaims(tokenString, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
			// Validate the signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(jwtSecret), nil
		})
		
		if err != nil {
			log.Printf("Error parsing token: %v", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		
		// Check if the token is valid
		if claims, ok := token.Claims.(*UserClaims); ok && token.Valid {
			// Add claims to request context
			ctx := context.WithValue(r.Context(), "userClaims", claims)
			r = r.WithContext(ctx)
			log.Printf("User authenticated: %s", claims.UserID)
			next.ServeHTTP(w, r)
			return
		}
		
		log.Println("Invalid token")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}

// authStatusHandler returns the current authentication status of the user
func (s *Server) authStatusHandler(w http.ResponseWriter, r *http.Request) {
	// Get the token from the Authorization header
	authHeader := r.Header.Get("Authorization")
	
	resp := make(map[string]interface{})
	
	// If no Authorization header, user is not authenticated
	if authHeader == "" || len(authHeader) <= 7 || authHeader[:7] != "Bearer " {
		resp["authenticated"] = false
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
		return
	}
	
	// Extract the token
	tokenString := authHeader[7:]
	
	// Parse and validate the token
	token, err := jwt.ParseWithClaims(tokenString, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtSecret), nil
	})
	
	if err != nil || !token.Valid {
		resp["authenticated"] = false
	} else if claims, ok := token.Claims.(*UserClaims); ok {
		resp["authenticated"] = true
		resp["user_id"] = claims.UserID
		resp["user_name"] = claims.Name
		resp["user_email"] = claims.Email
		resp["provider"] = claims.Provider
	} else {
		resp["authenticated"] = false
	}
	
	// Return JSON response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// protectedHandler is a sample protected route that requires authentication
func (s *Server) protectedHandler(w http.ResponseWriter, r *http.Request) {
	// Get the user claims from the context (set by the AuthMiddleware)
	claims, ok := r.Context().Value("userClaims").(*UserClaims)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	resp := map[string]interface{}{
		"message": "This is a protected route",
		"user_id": claims.UserID,
		"name": claims.Name,
		"email": claims.Email,
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// getUserProfileHandler returns the user's profile information from the database
func (s *Server) getUserProfileHandler(w http.ResponseWriter, r *http.Request) {
	// Get the user claims from the context (set by the AuthMiddleware)
	claims, ok := r.Context().Value("userClaims").(*UserClaims)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	// Get the user's OAuth account from the database
	account, err := s.db.GetOAuthAccountByID(claims.UserID, claims.Provider)
	if err != nil {
		log.Printf("Error retrieving OAuth account: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	
	if account == nil {
		// User not found in database
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	
	// Return the user profile as JSON
	response := map[string]interface{}{
		"id":        account.ID,
		"user_id":   account.UserID,
		"provider":  account.Provider,
		"email":     account.Email,
		"name":      account.Name,
		"avatar":    account.AvatarURL,
		"joined_at": account.CreatedAt,
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// getOAuthUserHandler returns the complete OAuth user data from the database
func (s *Server) getOAuthUserHandler(w http.ResponseWriter, r *http.Request) {
	// Get the user claims from the context (set by the AuthMiddleware)
	claims, ok := r.Context().Value("userClaims").(*UserClaims)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	// Get the user's OAuth account from the database
	account, err := s.db.GetOAuthAccountByID(claims.UserID, claims.Provider)
	if err != nil {
		log.Printf("Error retrieving OAuth account: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	
	if account == nil {
		// User not found in database
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	
	// Map the database record to a response object (hiding sensitive fields)
	response := map[string]interface{}{
		"id":             account.ID,
		"user_id":        account.UserID,
		"provider":       account.Provider,
		"email":          account.Email,
		"name":           account.Name,
		"first_name":     account.FirstName,
		"last_name":      account.LastName,
		"nickname":       account.NickName,
		"description":    account.Description,
		"avatar_url":     account.AvatarURL,
		"location":       account.Location,
		"access_token":   "[REDACTED]", // Don't expose actual token
		"token_expires":  account.ExpiresAt,
		"created_at":     account.CreatedAt,
		"updated_at":     account.UpdatedAt,
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

