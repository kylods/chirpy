package main

import (
	"fmt"
	"log"
	"net/http"

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
	})
}

// Called with any given call to fsHandler
func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits++
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) metricsRequest(w http.ResponseWriter, request *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	w.Write([]byte(fmt.Sprintf("Hits: %v", cfg.fileserverHits)))
}

func (cfg *apiConfig) metricsReset(w http.ResponseWriter, request *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	cfg.fileserverHits = 0
	w.Write([]byte("Reset Metrics."))
}

func main() {
	h1 := func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	}

	//Initialize router & apiConfig
	r := chi.NewRouter()
	apiCfg := apiConfig{}

	fsHandler := apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir("."))))

	//Handles routing to different 'directories'
	r.Handle("/app/*", fsHandler)
	r.Handle("/app", fsHandler)
	r.Get("/healthz", h1)
	r.Get("/metrics", apiCfg.metricsRequest)
	r.HandleFunc("/reset", apiCfg.metricsReset)

	corsMux := middlewareCors(r)

	//Initializes the server. Handler wraps ALL HTTP requests
	srv := &http.Server{
		Addr:    ":8080",
		Handler: corsMux,
	}

	//Starts listening indefinitely for requests.
	log.Fatal(srv.ListenAndServe())

}
