package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

var waf coraza.WAF

func initCoraza() error {
	config := coraza.NewWAFConfig().WithDirectives(`
		# Enable rule engine
		SecRuleEngine On

		# Example rule: Block requests containing 'malicious' in the URI
		SecRule REQUEST_URI "@contains malicious" "id:1,phase:1,deny,status:403,log,msg:'Potential malicious activity detected'"
	`)

	var err error
	waf, err = coraza.NewWAF(config)
	return err
}

func wafMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tx := waf.NewTransaction()
		defer func() {
			if tx.IsInterrupted() {
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprintln(w, "Request blocked by WAF")
				return
			}
			tx.ProcessLogging()
			if err := tx.Close(); err != nil {
				log.Printf("Error closing transaction: %v", err)
			}
		}()

		ir, err := tx.ProcessRequest(types.RequestData{
			Method:     r.Method,
			Headers:    r.Header,
			Address:    r.RemoteAddr,
			URI:        r.URL.String(),
			HTTPVersion: fmt.Sprintf("%d.%d", r.ProtoMajor, r.ProtoMinor),
		})
		if err != nil {
			log.Printf("Error processing request: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if ir != nil {
			return // Request was interrupted, response already sent
		}

		next.ServeHTTP(w, r)
	})
}

func main() {
	if err := initCoraza(); err != nil {
		log.Fatalf("Failed to initialize Coraza: %v", err)
	}

	backendURL, err := url.Parse("http://localhost:8080") // Change this to your backend service URL
	if err != nil {
		log.Fatalf("Invalid backend URL: %v", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(backendURL)
	
	http.Handle("/", wafMiddleware(proxy))

	log.Println("Starting WAF proxy on :8000...")
	if err := http.ListenAndServe(":8000", nil); err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
}
