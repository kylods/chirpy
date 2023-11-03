package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

// Used as a volatile in-memory counter, could be converted to be persistant by saving and reloading to/from disk
type apiConfig struct {
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

func postHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	type parameters struct {
		// these tags indicate how the keys in the JSON should be mapped to the struct fields
		// the struct fields must be exported (start with a capital letter) if you want them parsed
		Body string `json:"body"`
	}

	type responseValid struct {
		CleanedBody string `json:"cleaned_body"`
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

	respBody := responseValid{
		CleanedBody: cleanedChirp,
	}
	dat, _ := json.Marshal(respBody)
	w.WriteHeader(200)
	w.Write(dat)
	return
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

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {

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

func main() {
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

	fsHandler := apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir("."))))

	//Handles routing to different 'directories'
	r.Handle("/app/*", fsHandler)
	r.Handle("/app", fsHandler)
	apiR.Get("/healthz", h1)
	apiR.Post("/validate_chirp", postHandler)
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
