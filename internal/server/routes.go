package server

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/markbates/goth/gothic"
)

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
	
	// Get all cookies to debug
	cookies := r.Cookies()
	for _, cookie := range cookies {
		log.Printf("Cookie found: %s = %s", cookie.Name, cookie.Value)
	}

	// Try to complete the auth process
	user, err := gothic.CompleteUserAuth(w, r)
	if err != nil {
		log.Printf("Auth error: %v", err)
		http.Error(w, "Failed to complete user auth", http.StatusInternalServerError)
		return
	}

	log.Printf("User authenticated successfully: %s (%s)", user.Name, user.Email)

	http.Redirect(w, r, "http://localhost:3000", http.StatusFound)
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

