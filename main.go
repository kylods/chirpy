package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
)

type apiConfig struct {
	fileserverHits int
}

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

	r := chi.NewRouter()
	apiCfg := apiConfig{}

	fsHandler := apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir("."))))

	r.Handle("/app/*", fsHandler)
	r.Handle("/app", fsHandler)
	r.Get("/healthz", h1)
	r.Get("/metrics", apiCfg.metricsRequest)
	r.HandleFunc("/reset", apiCfg.metricsReset)
	corsMux := middlewareCors(r)

	srv := &http.Server{
		Addr:    ":8080",
		Handler: corsMux,
	}

	log.Fatal(srv.ListenAndServe())

}
