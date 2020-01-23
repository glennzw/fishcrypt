package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"time"

	"github.com/glennzw/fishcrypt"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"golang.org/x/crypto/bcrypt"
)

var db *gorm.DB
var CookieStore map[string]string // Maps session identifiers to usernames. Don't use in production, use gorilla/sessions

// store will hold all session data
var store *sessions.CookieStore

// UserAuth allows us to track user authentication for web page access (via gorilla/sessions)
type UserAuth struct {
	Username      string
	Authenticated bool
}

type pageMessage struct {
	Error bool
	Text  string
}

type User struct {
	Id         int64  `json:"id"`
	Username   string `json:"username" sql:"not null;unique"`
	Hash       string `json:"-"`
	PubKey     string `json:"pubkey"`
	EncPrivKey string `json:"encprivkey"`
}

type Data struct {
	Username string `json:"username"`
	EncData  string `json:"encdata"`
}

type TemplateData struct {
	UserInfo User
	UserData []Data
}

type Users struct {
	UserInfo []User
}

type passChange struct {
	OldPassword string `json:"oldpassword"`
	NewPassword string `json:"newpassword"`
}

type result struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type message struct {
	Username string `json:"username"`
	Text     string `json:"text"`
}

// Helper functions
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}
func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func dbsetup() {
	fmt.Println("[+] Setting up database")
	var err error
	db, err = gorm.Open("sqlite3", "database.db")
	if err != nil {
		panic(err)
	}
	// Create the table from our struct.
	db.AutoMigrate(&User{})
	db.AutoMigrate(&Data{})
}

func newRouter() *mux.Router {
	r := mux.NewRouter()
	r.HandleFunc("/", landing).Methods("GET")
	r.HandleFunc("/login", login).Methods("GET", "POST")
	r.HandleFunc("/logout", logout).Methods("GET", "POST")
	r.HandleFunc("/register", register).Methods("GET", "POST")
	r.HandleFunc("/profile/{state}", profile).Methods("GET")
	r.HandleFunc("/message", catchdata).Methods("GET", "POST")
	r.HandleFunc("/changepassword", changepassword).Methods("POST")

	staticFileDirectory := http.Dir("./static/")
	staticFileHandler := http.StripPrefix("/static/", http.FileServer(staticFileDirectory))
	r.PathPrefix("/static/").Handler(staticFileHandler).Methods("GET")

	return r
}

func catchdata(w http.ResponseWriter, r *http.Request) {

	if r.Method == http.MethodGet {
		messagePage, err := template.ParseFiles("./static/message.html")
		if err != nil {
			fmt.Println(err)
			fmt.Fprintf(w, "Error: Unable to parse template.")
		}
		var users []User
		var count int

		db.Model(&User{}).Find(&users).Count(&count)

		templateData := Users{UserInfo: users}
		messagePage.Execute(w, &templateData)
		return
	}

	var msg message
	err := json.NewDecoder(r.Body).Decode(&msg)
	if err != nil {
		fmt.Println(err)
		json.NewEncoder(w).Encode(result{Status: "error", Message: "Unable to parse JSON"})
		return
	}

	username := msg.Username
	data := msg.Text

	if data == "" {
		json.NewEncoder(w).Encode(result{Status: "error", Message: "No message text."})
		return
	}

	// Check if user exists
	var count int
	var user User
	db.Model(&User{}).Where("username = ?", username).First(&user).Count(&count)
	if count < 1 {
		json.NewEncoder(w).Encode(result{Status: "error", Message: "No such user."}) // User enumeration risk
		return
	}

	// Grab the public key for the user and encrypt the data
	pubKey := user.PubKey
	encData, err := fishcrypt.EncryptData(data, pubKey)
	if err != nil {
		json.NewEncoder(w).Encode(result{Status: "error", Message: "Unable to encrypt data for user."})
		return
	}

	// Save the encrypted data to the database
	dbData := Data{Username: user.Username, EncData: encData}
	db.Create(&dbData)

	tmp := fmt.Sprintf("Received data '%s' for user '%s' and encrypted it as '%s' in the database.", data, user.Username, encData)
	json.NewEncoder(w).Encode(result{Status: "success", Message: tmp})
}

// Check the session to retrieve matching user, or nil for no session
func isAuthenticated(r *http.Request, dec bool) (User, []Data, error) {

	// To store vars from db
	var count int
	var user User
	var data []Data

	// Check cookie table
	getsesh, err := r.Cookie("sessionid")
	if err != nil {
		return User{}, []Data{}, err
	}
	sessionid := getsesh.Value

	// Get private key from cookie
	getkey, err := r.Cookie("key")
	if err != nil {
		return User{}, []Data{}, err
	}
	key := getkey.Value

	// Check if cookie in map
	if username, ok := CookieStore[sessionid]; ok {
		db.Model(&User{}).Where("username = ?", username).First(&user)              // Load user data
		db.Model(&Data{}).Where("username = ?", username).Find(&data).Count(&count) // Get user's encrypted messages
	}

	if dec { // If requested decrypt messages with user's key
		var decData []Data
		for _, d := range data {
			d, err := fishcrypt.DecryptData(d.EncData, key)
			if err != nil {
				return User{}, []Data{}, err
			}
			decData = append(decData, Data{Username: user.Username, EncData: d})
		}
		return user, decData, nil
	}

	return user, data, nil

}

func changepassword(w http.ResponseWriter, r *http.Request) {

	user, _, _ := isAuthenticated(r, false)
	if user.Username == "" {
		json.NewEncoder(w).Encode(result{Status: "error", Message: "User not authenticated. Try refreshing page."})
		return
	}

	var pass passChange
	err := json.NewDecoder(r.Body).Decode(&pass) // Do I really have to create a struct for this?
	if err != nil {
		fmt.Println(err)
		json.NewEncoder(w).Encode(result{Status: "error", Message: "Unable to parse JSON"})
		return
	}

	oldpassword := pass.OldPassword
	newpassword := pass.NewPassword

	if !checkPasswordHash(oldpassword, user.Hash) {
		json.NewEncoder(w).Encode(result{Status: "error", Message: "Your old password is incorrect."})
	} else {

		newPassHash, _ := hashPassword(newpassword)
		newPrivKey, err := fishcrypt.UpdatePassword(user.EncPrivKey, oldpassword, newpassword)
		if err != nil {
			fmt.Println(err)
			json.NewEncoder(w).Encode(result{Status: "error", Message: "Error updating password."})
		} else {

			// Update user field with new hash and private key
			db.Model(&user).Updates(User{Hash: newPassHash, EncPrivKey: newPrivKey}) // TODO: Learn how to handle errors with gorm. Also rollback on fail.
			json.NewEncoder(w).Encode(result{Status: "success", Message: "Password successfully changed."})
		}

	}

}

func profile(w http.ResponseWriter, r *http.Request) {

	profile, _ := template.ParseFiles("./static/profile.html")

	vars := mux.Vars(r)
	state := vars["state"] // Display encrypted or decrypted data
	decdata := false
	if state == "dec" {
		decdata = true
	}

	user, data, err := isAuthenticated(r, decdata)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusFound) // No sessionid cookie set, redirect to main login page
	} else {
		if user.Username == "" {
			http.Redirect(w, r, "/", http.StatusFound) // No sessionid cookie set, redirect to main login page
		} else {
			// Load user's profile and messages
			templateData := TemplateData{UserInfo: user, UserData: data}
			profile.Execute(w, &templateData)
		}
	}

}

func login(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/profile/enc", http.StatusFound)
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	tmpl, _ := template.ParseFiles("./static/login.html")

	var count int
	var user User

	// Check user credentials
	db.Model(&User{}).Where("username = ?", username).First(&user).Count(&count)
	if count < 1 || !checkPasswordHash(password, user.Hash) { // Short circuit on the count
		tmpl.Execute(w, pageMessage{Error: true, Text: "Error: Bad credentials"})

	} else {
		// Set a session cookie and decrypted private key cookie and save it in our simple cookie store
		sessionid := uuid.New().String()
		CookieStore[sessionid] = username
		http.SetCookie(w, &http.Cookie{Name: "sessionid", Value: sessionid, Expires: time.Now().AddDate(0, 0, 1)})

		decPrivKey, err := fishcrypt.DecryptPrivateKey(user.EncPrivKey, password)
		if err != nil {
			fmt.Fprintf(w, "Error: Unable to load user's keys. Sorry.")
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "key", Value: decPrivKey, Expires: time.Now().AddDate(0, 0, 1)})

		http.Redirect(w, r, "/profile/enc", http.StatusFound)
	}
}

func logout(w http.ResponseWriter, r *http.Request) {

	getsesh, err := r.Cookie("sessionid")
	if err != nil {
		http.Redirect(w, r, "/", http.StatusFound)
	}
	sessionid := getsesh.Value
	delete(CookieStore, sessionid)
	http.Redirect(w, r, "/", http.StatusFound)

}

func register(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusFound)
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	tmpl, _ := template.ParseFiles("./static/login.html")

	if username == "" || password == "" {
		tmpl.Execute(w, pageMessage{Error: true, Text: "Error: Please enter a username and password when registering"})
		return
	}

	// Check if user already exists
	var count int
	db.Model(&User{}).Where("username = ?", username).Count(&count)
	if count > 0 {
		tmpl.Execute(w, pageMessage{Error: true, Text: "Error: User already exists"})
		return
	}

	// Create keys for new user
	pubKey, privKey, _ := fishcrypt.CreateKeys(password)
	passHash, _ := hashPassword(password)

	newUser := User{Username: username, Hash: passHash, PubKey: pubKey, EncPrivKey: privKey}
	db.Create(&newUser)

	msg := pageMessage{Error: false, Text: "Successfully registered new user, please login."}

	tmpl.Execute(w, msg)

}

func landing(w http.ResponseWriter, r *http.Request) {
	tmpl, _ := template.ParseFiles("./static/login.html")

	// Check if user already logged in and redirect to profile page
	u, _, _ := isAuthenticated(r, false)
	if u.Username != "" {
		http.Redirect(w, r, "/profile/enc", http.StatusFound)
		return
	}

	msg := pageMessage{Error: false, Text: ""}
	tmpl.Execute(w, msg)
}

func main() {

	port := os.Getenv("PORT") // For easy deployment to Heroku

	if port == "" {
		fmt.Println("[!] $PORT not set, using default of 8000")
		port = "8000"
	}

	dbsetup()
	CookieStore = make(map[string]string) // Initialise our session tracker
	r := newRouter()
	fmt.Printf("[+] Starting server on port '%s'\n", port)
	http.ListenAndServe(":"+port, r)

}
