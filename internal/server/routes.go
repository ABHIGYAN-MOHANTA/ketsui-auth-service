package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
)

// JWT expiry time
const jwtExpiry = 24 * time.Hour

// UserClaims represents the JWT claims
type UserClaims struct {
	UserID    string `json:"user_id"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	Provider  string `json:"provider"`
	AvatarURL string `json:"avatar_url"`
	jwt.RegisteredClaims
}

func (s *Server) RegisterRoutes() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
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

	log.Println("Registering auth routes...")
	r.Get("/auth/{provider}", s.beginAuthHandler)
	r.Get("/auth/{provider}/", s.beginAuthHandler)
	r.Get("/auth/{provider}/callback", s.getAuthCallback)
	r.Get("/auth/{provider}/callback/", s.getAuthCallback)
	log.Printf("Registered auth routes with and without trailing slashes")

	r.Get("/auth/status", s.authStatusHandler)

	r.Group(func(r chi.Router) {
		r.Use(s.AuthMiddleware)
		r.Get("/protected", s.protectedHandler)
		r.Get("/user/profile", s.getUserProfileHandler)
		r.Get("/oauth/user", s.getOAuthUserHandler)
	})

	r.Get("/logout/{provider}", s.logoutHandler)
	r.Get("/logout/{provider}/", s.logoutHandler)

	return r
}

func (s *Server) HelloWorldHandler(w http.ResponseWriter, r *http.Request) {
	resp := map[string]string{"message": "Hello World"}
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

	provider := chi.URLParam(r, "provider")
	log.Printf("Auth callback for provider: %s", provider)
	r = r.WithContext(context.WithValue(r.Context(), "provider", provider))

	user, err := gothic.CompleteUserAuth(w, r)
	if err != nil {
		log.Printf("Auth error: %v", err)
		http.Error(w, "Failed to complete user auth", http.StatusInternalServerError)
		return
	}

	log.Printf("User authenticated successfully: %s (%s)", user.Name, user.Email)

	oauthAccount, err := s.db.StoreOAuthAccount(user)
	if err != nil {
		log.Printf("Error storing OAuth account: %v", err)
	} else {
		log.Printf("OAuth account stored/updated successfully. ID: %d", oauthAccount.ID)
	}

	token, err := createJWTToken(user, provider)
	if err != nil {
		log.Printf("Error creating JWT: %v", err)
		http.Error(w, "Authentication server error", http.StatusInternalServerError)
		return
	}

	clientRedirectURL := os.Getenv("CLIENT_REDIRECT_URL")
	redirectURL := fmt.Sprintf("%s?token=%s", clientRedirectURL, token)
	log.Printf("Redirecting to: %s", redirectURL)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (s *Server) beginAuthHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received auth request: %s %s", r.Method, r.URL.Path)

	provider := chi.URLParam(r, "provider")
	log.Printf("Auth provider from URL parameter: %s", provider)
	r = r.WithContext(context.WithValue(r.Context(), "provider", provider))

	cookies := r.Cookies()
	log.Printf("Found %d cookies in the request", len(cookies))
	for _, cookie := range cookies {
		log.Printf("Cookie: %s=%s", cookie.Name, cookie.Value)
	}

	session, _ := gothic.Store.Get(r, gothic.SessionName)
	session.Values["provider"] = provider
	if err := session.Save(r, w); err != nil {
		log.Printf("Error saving session: %v", err)
	} else {
		log.Printf("Session saved successfully with provider: %s", provider)
	}

	if user, err := gothic.CompleteUserAuth(w, r); err == nil {
		log.Printf("User already authenticated: %v", user)
		jsonResp, _ := json.Marshal(user)
		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonResp)
		return
	}

	log.Printf("Beginning auth flow for provider: %s", provider)
	gothic.BeginAuthHandler(w, r)
}

func (s *Server) logoutHandler(w http.ResponseWriter, r *http.Request) {
	err := gothic.Logout(w, r)
	if err != nil {
		http.Error(w, "Failed to logout", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func createJWTToken(user goth.User, provider string) (string, error) {
	expiryTime := time.Now().Add(jwtExpiry)

	claims := UserClaims{
		UserID:    user.UserID,
		Email:     user.Email,
		Name:      user.Name,
		Provider:  provider,
		AvatarURL: user.AvatarURL,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiryTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "ketsui-auth-service",
			Subject:   user.UserID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	secret := getJWTSecret()

	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (s *Server) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("Checking JWT authentication")

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			log.Println("No Authorization header found")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if len(authHeader) <= 7 || authHeader[:7] != "Bearer " {
			log.Println("Invalid Authorization format")
			http.Error(w, "Invalid Authorization format", http.StatusUnauthorized)
			return
		}

		tokenString := authHeader[7:]

		token, err := jwt.ParseWithClaims(tokenString, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(getJWTSecret()), nil
		})

		if err != nil {
			log.Printf("Error parsing token: %v", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if claims, ok := token.Claims.(*UserClaims); ok && token.Valid {
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

func (s *Server) authStatusHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	resp := make(map[string]interface{})

	if authHeader == "" || len(authHeader) <= 7 || authHeader[:7] != "Bearer " {
		resp["authenticated"] = false
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
		return
	}

	tokenString := authHeader[7:]

	token, err := jwt.ParseWithClaims(tokenString, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(getJWTSecret()), nil
	})

	if err != nil || !token.Valid {
		resp["authenticated"] = false
	} else if claims, ok := token.Claims.(*UserClaims); ok {
		resp["authenticated"] = true
		resp["user_id"] = claims.UserID
		resp["user_name"] = claims.Name
		resp["user_email"] = claims.Email
		resp["provider"] = claims.Provider
		resp["avatar_url"] = claims.AvatarURL
	} else {
		resp["authenticated"] = false
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) protectedHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value("userClaims").(*UserClaims)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	resp := map[string]interface{}{
		"message":    "This is a protected route",
		"user_id":    claims.UserID,
		"name":       claims.Name,
		"email":      claims.Email,
		"provider":   claims.Provider,
		"avatar_url": claims.AvatarURL,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) getUserProfileHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value("userClaims").(*UserClaims)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	account, err := s.db.GetOAuthAccountByID(claims.UserID, claims.Provider)
	if err != nil {
		log.Printf("Error retrieving OAuth account: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	if account == nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

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

func (s *Server) getOAuthUserHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value("userClaims").(*UserClaims)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	account, err := s.db.GetOAuthAccountByID(claims.UserID, claims.Provider)
	if err != nil {
		log.Printf("Error retrieving OAuth account: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	if account == nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	response := map[string]interface{}{
		"id":            account.ID,
		"user_id":       account.UserID,
		"provider":      account.Provider,
		"email":         account.Email,
		"name":          account.Name,
		"first_name":    account.FirstName,
		"last_name":     account.LastName,
		"nickname":      account.NickName,
		"description":   account.Description,
		"avatar_url":    account.AvatarURL,
		"location":      account.Location,
		"access_token":  "[REDACTED]",
		"token_expires": account.ExpiresAt,
		"created_at":    account.CreatedAt,
		"updated_at":    account.UpdatedAt,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// getJWTSecret retrieves JWT secret from environment
func getJWTSecret() string {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		log.Fatal("JWT_SECRET environment variable not set")
	}
	return secret
}
