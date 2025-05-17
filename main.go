package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/coreos/go-oidc"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

var (
	clientID     = "go"
	clientSecret = "*"
	redirectURL  = "http://localhost:9090/callback"
	keycloakURL  = "http://localhost:8888/realms/go"

	provider     *oidc.Provider
	oauth2Config *oauth2.Config
	verifier     *oidc.IDTokenVerifier
)
var store = sessions.NewCookieStore([]byte("super-secret-key"))

func main() {
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600 * 8, // 8 часов
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   true, // если HTTPS, иначе false
	}
	ctx := context.Background()

	var err error
	provider, err = oidc.NewProvider(ctx, keycloakURL)
	if err != nil {
		log.Fatalf("Failed to get provider: %v", err)
	}

	oauth2Config = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	verifier = provider.Verifier(&oidc.Config{ClientID: clientID})

	http.HandleFunc("/", handleRoot)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)
	http.HandleFunc("/dashboard", handleDashboard)
	http.HandleFunc("/submit", handleSubmit)

	fmt.Println("Server started at http://localhost:9090")
	log.Fatal(http.ListenAndServe(":9090", nil))
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	if session.Values["authenticated"] == true {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
	} else {
		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, oauth2Config.AuthCodeURL("state"), http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		http.Error(w, errMsg, http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Code not found", http.StatusBadRequest)
		return
	}

	token, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in token", http.StatusInternalServerError)
		return
	}

	_, err = verifier.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	session, _ := store.Get(r, "session")
	session.Values["authenticated"] = true
	session.Values["id_token"] = rawIDToken
	session.Save(r, w)

	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	if session.Values["authenticated"] != true {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	html := `
    <!DOCTYPE html>
    <html>
    <head><title>Dashboard</title></head>
    <body>
        <h1>Welcome to your dashboard!</h1>
        <form action="/submit" method="post" enctype="multipart/form-data">
            <textarea name="comment" rows="4" cols="50" placeholder="Enter your comment"></textarea><br><br>
            <input type="file" name="uploadfile"><br><br>
            <input type="submit" value="Submit">
        </form>
    </body>
    </html>
    `
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

func handleSubmit(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	if session.Values["authenticated"] != true {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	err := r.ParseMultipartForm(10 << 20)
	if err != nil {
		http.Error(w, "Failed to parse form: "+err.Error(), http.StatusBadRequest)
		return
	}

	comment := r.FormValue("comment")

	file, handler, err := r.FormFile("uploadfile")
	if err != nil {
		http.Error(w, "Error retrieving the file: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	f, err := os.Create(handler.Filename)
	if err != nil {
		http.Error(w, "Failed to save file: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()

	_, err = io.Copy(f, file)
	if err != nil {
		http.Error(w, "Failed to write file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "Comment received: %s\n", comment)
	fmt.Fprintf(w, "File uploaded: %s\n", handler.Filename)
}
