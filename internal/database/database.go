package database

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"sort"
	"sync"

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
	ID   int    `json:"id"`
	Body string `json:"body"`
}

type User struct {
	Email string `json:"email"`
	Hash  []byte `json:"hash"`
	ID    int    `json:"id"`
}

func (u *User) stripSensitiveData() SafeUser {
	safeUser := SafeUser{
		Email: u.Email,
		ID:    u.ID,
	}
	return safeUser
}

type SafeUser struct {
	Email string `json:"email"`
	ID    int    `json:"id"`
}

type DBStructure struct {
	Chirps map[int]Chirp `json:"chirps"`
	Users  map[int]User  `json:"users"`
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
func (db *DB) CreateUser(email, password string) (SafeUser, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return SafeUser{}, err
	}
	user := User{Email: email, Hash: hash}
	err = db.createEntity(&user)
	if err != nil {
		return SafeUser{}, err
	}
	safeUser := user.stripSensitiveData()
	return safeUser, err
}

func (db *DB) AuthenticateUser(email, password string) (SafeUser, error) {
	user, err := db.fetchUser(email)
	if err != nil {
		return SafeUser{}, err
	}
	err = bcrypt.CompareHashAndPassword(user.Hash, []byte(password))
	if err != nil {
		return SafeUser{}, err
	}
	safeUser := SafeUser{
		Email: user.Email,
		ID:    user.ID,
	}
	return safeUser, nil
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
		return User{}, errors.New("User with that email already exists")
	}
	return User{}, errors.New("User does not exist")
}

// CreateChirp creates a new chirp and saves it to disk
func (db *DB) CreateChirp(body string) (Chirp, error) {
	chirp := Chirp{Body: body}
	err := db.createEntity(&chirp)
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
				Chirps: make(map[int]Chirp),
				Users:  make(map[int]User),
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
