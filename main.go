package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/joho/godotenv"
	"github.com/kylods/chirpy/internal/database"
)

var db *database.DB

// Used as a volatile in-memory counter, could be converted to be persistant by saving and reloading to/from disk
type apiConfig struct {
	jwtSecret      string
	fileserverHits int
}

// Called with any given HTTP request to the server
func middlewareCors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
		fmt.Println("Accessed: ", r.URL)
	})
}

// Called with any given call to fsHandler
func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits++
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) metricsRequest(w http.ResponseWriter, re *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(200)

	response := fmt.Sprintf(`<html>

	<body>
		<h1>Welcome, Chirpy Admin</h1>
		<p>Chirpy has been visited %d times!</p>
	</body>
	
	</html>`, cfg.fileserverHits)

	w.Write([]byte(response))
}

func (cfg *apiConfig) metricsReset(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	cfg.fileserverHits = 0
	w.Write([]byte("Reset Metrics."))
}

func (cfg *apiConfig) authenticateLogin(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		// these tags indicate how the keys in the JSON should be mapped to the struct fields
		// the struct fields must be exported (start with a capital letter) if you want them parsed
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		// an error will be thrown if the JSON is invalid or has the wrong types
		// any missing fields will simply have their values in the struct set to their zero value
		log.Printf("Error decoding parameters: %s", err)
		respondWithError(w, 500, "Something went wrong")
		return
	}

	safeUser, err := db.AuthenticateUser(params.Email, params.Password)
	if err != nil {
		respondWithError(w, 401, err.Error())
		return
	}

	respondWithJSON(w, 200, safeUser)
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	dat, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Error encoding parameters: %s", err)
		respondWithError(w, 500, "Something went wrong")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(dat)
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
	response := struct {
		Error string `json:"error"`
	}{
		Error: msg,
	}
	dat, _ := json.Marshal(response)
	w.WriteHeader(code)
	w.Write(dat)
}

func cleanChirp(dirtyChirp string) string {
	badWords := []string{"kerfuffle", "sharbert", "fornax"}
	chirpWords := strings.Split(dirtyChirp, " ")

	for i, word := range chirpWords {
		for _, badWord := range badWords {
			lowerWord := strings.ToLower(word)
			if lowerWord == badWord {
				chirpWords[i] = "****"
			}
		}
	}

	cleanedChirp := strings.Join(chirpWords, " ")
	return cleanedChirp
}

func getChirps(w http.ResponseWriter, r *http.Request) {
	chirps, err := db.GetChirps()
	if err != nil {
		log.Printf("Error loading from db: %v", err)
		respondWithError(w, 500, err.Error())
		return
	}
	respondWithJSON(w, 200, chirps)
}

func getChirpById(w http.ResponseWriter, r *http.Request) {
	chirps, err := db.GetChirps()
	if err != nil {
		log.Printf("Error loading from db: %v", err)
		respondWithError(w, 500, err.Error())
		return
	}
	chirpID, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		log.Printf("Error parsing id: %v", err)
		respondWithError(w, 500, err.Error())
		return
	}
	if chirpID > len(chirps) {
		respondWithError(w, 404, "Resource does not exist")
		return
	}

	chirpIndex := chirpID - 1
	chirp := chirps[chirpIndex]

	respondWithJSON(w, 200, chirp)
}

func postChirps(w http.ResponseWriter, r *http.Request) {

	type parameters struct {
		// these tags indicate how the keys in the JSON should be mapped to the struct fields
		// the struct fields must be exported (start with a capital letter) if you want them parsed
		Body string `json:"body"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		// an error will be thrown if the JSON is invalid or has the wrong types
		// any missing fields will simply have their values in the struct set to their zero value
		log.Printf("Error decoding parameters: %s", err)
		respondWithError(w, 500, "Something went wrong")
		return
	}

	//params is a struct with successfully populated data

	if len(params.Body) > 140 {
		log.Printf("Chirp too long; %v", len(params.Body))
		respondWithError(w, 400, "Chirp is too long")
		return
	}

	cleanedChirp := cleanChirp(params.Body)

	chirp, err := db.CreateChirp(cleanedChirp)
	if err != nil {
		log.Printf("Error saving chirp to db: %v", err)
		respondWithError(w, 500, err.Error())
	}

	respondWithJSON(w, 201, chirp)
}

func addUser(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		// these tags indicate how the keys in the JSON should be mapped to the struct fields
		// the struct fields must be exported (start with a capital letter) if you want them parsed
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		// an error will be thrown if the JSON is invalid or has the wrong types
		// any missing fields will simply have their values in the struct set to their zero value
		log.Printf("Error decoding parameters: %s", err)
		respondWithError(w, 500, "Something went wrong")
		return
	}

	if len(params.Password) == 0 {
		respondWithError(w, 400, "Password cannot be empty")
		return
	}
	//params is a struct with successfully populated data

	user, err := db.CreateUser(params.Email, params.Password)
	if err != nil {
		respondWithError(w, 500, err.Error())
		return
	}

	respondWithJSON(w, 201, user)
}

func main() {
	// by default, godotenv will look for a file named .env in the current directory
	godotenv.Load()
	dbPath := "./database.json"

	//Checks for debug flag, deletes database if true
	dbg := flag.Bool("debug", false, "Enable debug mode")
	flag.Parse()
	if *dbg {
		os.Remove(dbPath)
	}

	var err error
	db, err = database.NewDB(dbPath)
	if err != nil {
		log.Fatal("Database failed to initialize: ", err)
	}

	h1 := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	}

	//Initialize router & apiConfig
	r := chi.NewRouter()
	apiR := chi.NewRouter()
	adminR := chi.NewRouter()

	apiCfg := apiConfig{}
	apiCfg.jwtSecret = os.Getenv("JWT_SECRET")

	fsHandler := apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir("."))))

	//Handles routing to different 'directories'
	r.Handle("/app/*", fsHandler)
	r.Handle("/app", fsHandler)
	apiR.Post("/users", addUser)
	apiR.Post("/login", apiCfg.authenticateLogin)
	apiR.Get("/chirps", getChirps)
	apiR.Get("/chirps/{id}", getChirpById)
	apiR.Post("/chirps", postChirps)
	apiR.Get("/healthz", h1)
	adminR.Get("/metrics", apiCfg.metricsRequest)
	apiR.HandleFunc("/reset", apiCfg.metricsReset)

	corsMux := middlewareCors(r)
	r.Mount("/api", apiR)
	r.Mount("/admin", adminR)

	//Initializes the server. Handler wraps ALL HTTP requests
	srv := &http.Server{
		Addr:    ":8080",
		Handler: corsMux,
	}

	//Starts listening indefinitely for requests.
	log.Fatal(srv.ListenAndServe())

}
