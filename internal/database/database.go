package database

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type DBEntity interface {
	AssignID(dbStructure *DBStructure)
}

func (u *User) AssignID(dbStructure *DBStructure) {
	id := len(dbStructure.Users) + 1
	u.ID = id
}

func (c *Chirp) AssignID(dbStructure *DBStructure) {
	id := len(dbStructure.Chirps) + 1
	c.ID = id
}

type DB struct {
	path string
	mux  *sync.RWMutex
}

type Chirp struct {
	ID       int    `json:"id"`
	AuthorID int    `json:"author_id"`
	Body     string `json:"body"`
}

type User struct {
	Email       string `json:"email"`
	Hash        []byte `json:"hash"`
	ID          int    `json:"id"`
	IsChirpyRed bool   `json:"is_chirpy_red"`
}

func (u *User) stripSensitiveData() SafeData {
	safeUser := SafeData{
		Email:       u.Email,
		ID:          u.ID,
		IsChirpyRed: u.IsChirpyRed,
	}
	return safeUser
}

type SafeData struct {
	Email        string `json:"email,omitempty"`
	ID           int    `json:"id,omitempty"`
	AccessToken  string `json:"token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IsChirpyRed  bool   `json:"is_chirpy_red"`
}

type DBStructure struct {
	Chirps        map[int]Chirp        `json:"chirps"`
	Users         map[int]User         `json:"users"`
	RevokedTokens map[string]time.Time `json:"revoked_tokens"`
}

func (db *DB) createEntity(entity DBEntity) error {
	dbStructure, err := db.loadDB()
	if err != nil {
		return err
	}

	switch e := entity.(type) {
	case *User:
		for _, u := range dbStructure.Users {
			if e.Email == u.Email {
				return errors.New("User with that email already exists")
			}
		}
		e.AssignID(&dbStructure)
		dbStructure.Users[e.ID] = *e
	case *Chirp:
		e.AssignID(&dbStructure)
		dbStructure.Chirps[e.ID] = *e
	default:
		return errors.New("unknown entity type")
	}

	return db.writeDB(dbStructure)
}

// NewDB creates a new database connection
// and creates the database file if it doesn't exist
func NewDB(path string) (*DB, error) {
	db := DB{
		path: path,
		mux:  &sync.RWMutex{},
	}
	err := db.ensureDB()
	if err != nil {
		return nil, err
	}
	return &db, nil
}

// CreateUser creates a new user and saves it to disk
func (db *DB) CreateUser(email, password string) (SafeData, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return SafeData{}, err
	}
	user := User{Email: email, Hash: hash, IsChirpyRed: false}
	err = db.createEntity(&user)
	if err != nil {
		return SafeData{}, err
	}
	safeUser := user.stripSensitiveData()
	return safeUser, err
}

func (db *DB) AuthenticateUser(email, password, jwtSecret string) (SafeData, error) {
	user, err := db.fetchUser(email)
	if err != nil {
		return SafeData{}, err
	}
	err = bcrypt.CompareHashAndPassword(user.Hash, []byte(password))
	if err != nil {
		return SafeData{}, err
	}

	accessTokenString, err := generateToken(user.ID, "chirpy-access", jwtSecret, time.Hour)
	if err != nil {
		return SafeData{}, err
	}
	refreshTokenString, err := generateToken(user.ID, "chirpy-refresh", jwtSecret, time.Hour*1440)
	if err != nil {
		return SafeData{}, err
	}
	userToken := SafeData{
		Email:        user.Email,
		ID:           user.ID,
		IsChirpyRed:  user.IsChirpyRed,
		AccessToken:  accessTokenString,
		RefreshToken: refreshTokenString,
	}
	return userToken, nil
}

func generateToken(userID int, issuer, jwtSecret string, timeToExpire time.Duration) (string, error) {
	claims := jwt.RegisteredClaims{
		Issuer:    issuer,
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(timeToExpire)),
		Subject:   fmt.Sprint(userID),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func (db *DB) UpdateUser(tokenString, newEmail, newPassword, jwtSecret string) (SafeData, error) {
	token, err := verifyToken(tokenString, jwtSecret)
	if err != nil {
		// Handle the error (it could be a signature error, token expired, etc.)
		return SafeData{}, err
	}
	if issuer, err := token.Claims.GetIssuer(); err != nil || issuer != "chirpy-access" {
		return SafeData{}, errors.New("invalid token")
	}

	userIDStr, err := token.Claims.GetSubject()
	if err != nil {
		return SafeData{}, err
	}
	userIdInt, err := strconv.Atoi(userIDStr)
	if err != nil {
		return SafeData{}, err
	}

	dbStructure, err := db.loadDB()
	if err != nil {
		return SafeData{}, err
	}

	user := dbStructure.Users[userIdInt]
	if newEmail != "" {
		user.Email = newEmail
	}
	if newPassword != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			return SafeData{}, err
		}
		user.Hash = hash
	}
	dbStructure.Users[userIdInt] = user
	err = db.writeDB(dbStructure)
	if err != nil {
		return SafeData{}, err
	}
	return user.stripSensitiveData(), nil
}

func verifyToken(tokenString, jwtSecret string) (*jwt.Token, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(jwtSecret), nil
	})
	if err != nil {
		// Handle the error (it could be a signature error, token expired, etc.)
		return nil, err
	}
	return token, nil
}

func (db *DB) RevokeToken(refreshTokenStr, jwtSecret string) error {
	token, err := verifyToken(refreshTokenStr, jwtSecret)
	if err != nil {
		// Handle the error (it could be a signature error, token expired, etc.)
		return err
	}
	if issuer, err := token.Claims.GetIssuer(); err != nil || issuer != "chirpy-refresh" {
		return errors.New("invalid token")
	}

	dbStructure, err := db.loadDB()
	if err != nil {
		return err
	}
	if _, ok := dbStructure.RevokedTokens[refreshTokenStr]; ok {
		return errors.New("invalid token")
	}

	dbStructure.RevokedTokens[refreshTokenStr] = time.Now()
	db.writeDB(dbStructure)
	return nil
}

func (db *DB) UpgradeUser(userID int) error {
	dbStructure, err := db.loadDB()
	if err != nil {
		return err
	}
	user, ok := dbStructure.Users[userID]
	if !ok {
		return errors.New("user does not exist")
	}
	user.IsChirpyRed = true
	dbStructure.Users[userID] = user
	err = db.writeDB(dbStructure)
	if err != nil {
		return err
	}
	return nil
}

func (db *DB) DeleteChirp(chirpID int, tokenStr, jwtSecret string) error {
	token, err := verifyToken(tokenStr, jwtSecret)
	if err != nil {
		// Handle the error (it could be a signature error, token expired, etc.)
		return err
	}
	if issuer, err := token.Claims.GetIssuer(); err != nil || issuer != "chirpy-access" {
		return errors.New("invalid token")
	}

	dbStructure, err := db.loadDB()
	if err != nil {
		return err
	}

	userIDStr, err := token.Claims.GetSubject()
	if err != nil {
		return err
	}
	userIDInt, err := strconv.Atoi(userIDStr)
	if err != nil {
		return err
	}

	if dbStructure.Chirps[chirpID].AuthorID != userIDInt {
		return errors.New("unauthorized")
	}
	dbStructure.Chirps[chirpID] = Chirp{}
	db.writeDB(dbStructure)

	return nil
}

func (db *DB) RenewToken(refreshTokenStr, jwtSecret string) (SafeData, error) {
	token, err := verifyToken(refreshTokenStr, jwtSecret)
	if err != nil {
		// Handle the error (it could be a signature error, token expired, etc.)
		return SafeData{}, err
	}
	if issuer, err := token.Claims.GetIssuer(); err != nil || issuer != "chirpy-refresh" {
		return SafeData{}, errors.New("invalid token")
	}

	//Check if token has been revoked
	dbStructure, err := db.loadDB()
	if err != nil {
		return SafeData{}, err
	}
	if _, ok := dbStructure.RevokedTokens[refreshTokenStr]; ok {
		return SafeData{}, errors.New("invalid token")
	}

	//Extract userID to create new access token
	userIDStr, err := token.Claims.GetSubject()
	if err != nil {
		return SafeData{}, err
	}
	userIDInt, err := strconv.Atoi(userIDStr)
	if err != nil {
		return SafeData{}, err
	}

	accessTokenStr, err := generateToken(userIDInt, "chirpy-access", jwtSecret, time.Hour)
	if err != nil {
		return SafeData{}, err
	}
	accessToken := SafeData{
		AccessToken: accessTokenStr,
	}
	return accessToken, nil
}

func (db *DB) fetchUser(email string) (User, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return User{}, err
	}
	for _, u := range dbStructure.Users {
		if email == u.Email {
			return u, nil
		}
	}
	return User{}, errors.New("User does not exist")
}

// CreateChirp creates a new chirp and saves it to disk
func (db *DB) CreateChirp(body, tokenStr, jwtSecret string) (Chirp, error) {
	token, err := verifyToken(tokenStr, jwtSecret)
	if err != nil {
		return Chirp{}, err
	}
	if issuer, err := token.Claims.GetIssuer(); err != nil || issuer != "chirpy-access" {
		return Chirp{}, errors.New("invalid token")
	}

	userIDStr, err := token.Claims.GetSubject()
	if err != nil {
		return Chirp{}, err
	}
	userIDInt, err := strconv.Atoi(userIDStr)
	if err != nil {
		return Chirp{}, err
	}

	chirp := Chirp{
		AuthorID: userIDInt,
		Body:     body,
	}
	err = db.createEntity(&chirp)
	if err != nil {
		return Chirp{}, err
	}
	return chirp, err
}

// GetChirps returns all chirps in the database
func (db *DB) GetChirps() ([]Chirp, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return nil, err
	}

	chirps := make([]Chirp, 0, len(dbStructure.Chirps))
	for _, value := range dbStructure.Chirps {
		chirps = append(chirps, value)
	}
	sort.Slice(chirps, func(i, j int) bool { return chirps[i].ID < chirps[j].ID })

	return chirps, nil
}

// ensureDB creates a new database file if it doesn't exist
func (db *DB) ensureDB() error {
	_, err := os.ReadFile(db.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			payload := DBStructure{
				Chirps:        make(map[int]Chirp),
				Users:         make(map[int]User),
				RevokedTokens: make(map[string]time.Time),
			}
			data, err := json.Marshal(payload)
			if err != nil {
				return err
			}
			err = os.WriteFile(db.path, data, 0777)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}
	return nil
}

// loadDB reads the database file into memory
func (db *DB) loadDB() (DBStructure, error) {
	db.mux.RLock()
	defer db.mux.RUnlock()

	dbStructure := DBStructure{}
	dbFile, err := os.ReadFile(db.path)
	if err != nil {
		return dbStructure, err
	}

	err = json.Unmarshal(dbFile, &dbStructure)
	if err != nil {
		return dbStructure, err
	}

	return dbStructure, nil
}

// writeDB writes the database file to disk
func (db *DB) writeDB(dbStructure DBStructure) error {
	db.mux.Lock()
	defer db.mux.Unlock()

	jsonData, err := json.Marshal(dbStructure)
	if err != nil {
		return err
	}
	err = os.WriteFile(db.path, jsonData, 0777)
	if err != nil {
		return err
	}
	return nil
}
