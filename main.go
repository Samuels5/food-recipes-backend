package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

// Structs for the Hasura request/response
type HasuraGraphQLRequest struct {
	Query     string      `json:"query"`
	Variables interface{} `json:"variables"`
}

type User struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginRequest struct for the login payload
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// HasuraUserResponse helps in parsing the user data from Hasura
type HasuraUserResponse struct {
	Data struct {
		Users []struct {
			ID       string `json:"id"`
			Email    string `json:"email"`
			Password string `json:"password"`
		} `json:"users"`
	} `json:"data"`
}

func main() {
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)

	fmt.Println("Go server starting on port 8081...")
	log.Fatal(http.ListenAndServe(":8081", nil))
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	// Set CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	// Handle preflight request
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// 1. Decode the user data
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	// 2. Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}

	// 3. Send the data to Hasura
	// Create a new user object with the hashed password
	newUser := User{
		Username: user.Username,
		Email:    user.Email,
		Password: string(hashedPassword),
	}

	// Define the GraphQL mutation
	mutation := `
		mutation insert_users_one($object: users_insert_input!) {
			insert_users_one(object: $object) {
				id
				username
			}
		}
	`

	// Create the request body
	reqBody := HasuraGraphQLRequest{
		Query: mutation,
		Variables: struct {
			Object User `json:"object"`
		}{Object: newUser},
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		http.Error(w, "Error creating request body", http.StatusInternalServerError)
		return
	}

	// Create the HTTP request to Hasura
	hasuraURL := "http://localhost:8080/v1/graphql"
	httpReq, err := http.NewRequest("POST", hasuraURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		http.Error(w, "Error creating request to Hasura", http.StatusInternalServerError)
		return
	}

	// Set headers
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-hasura-admin-secret", "myadminsecretkey")

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(httpReq)
	if err != nil {
		http.Error(w, "Error sending request to Hasura", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Check the response
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		log.Printf("Error from Hasura: %s", string(body))
		http.Error(w, "Error saving user to database", http.StatusInternalServerError)
		return
	}

	log.Printf("Successfully inserted user: %s", string(body))

	// 4. Return a final success response
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "User registered successfully!")
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	// Set CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	// Handle preflight request
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// 1. Decode the login data
	var loginReq LoginRequest
	err := json.NewDecoder(r.Body).Decode(&loginReq)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	// 2. Query Hasura for the user by email
	query := `
		query GetUserByEmail($email: String!) {
			users(where: {email: {_eq: $email}}) {
				id
				email
				password
			}
		}
	`

	reqBody := HasuraGraphQLRequest{
		Query: query,
		Variables: struct {
			Email string `json:"email"`
		}{Email: loginReq.Email},
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		http.Error(w, "Error creating request body", http.StatusInternalServerError)
		return
	}

	hasuraURL := "http://localhost:8080/v1/graphql"
	httpReq, err := http.NewRequest("POST", hasuraURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		http.Error(w, "Error creating request to Hasura", http.StatusInternalServerError)
		return
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-hasura-admin-secret", "myadminsecretkey")

	client := &http.Client{}
	resp, err := client.Do(httpReq)
	if err != nil {
		http.Error(w, "Error sending request to Hasura", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		log.Printf("Error from Hasura: %s", string(body))
		http.Error(w, "Error fetching user from database", http.StatusInternalServerError)
		return
	}

	var hasuraResp HasuraUserResponse
	err = json.Unmarshal(body, &hasuraResp)
	if err != nil {
		log.Printf("Error decoding Hasura response: %s", err)
		http.Error(w, "Error processing database response", http.StatusInternalServerError)
		return
	}

	if len(hasuraResp.Data.Users) == 0 {
		log.Println("User not found")
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	foundUser := hasuraResp.Data.Users[0]
	log.Printf("Found user: %+v", foundUser)

	// (Next Step) Compare password and generate JWT

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Login endpoint hit successfully! User found.")
}
