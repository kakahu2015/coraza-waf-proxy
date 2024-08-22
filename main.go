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

func init() {
	var err error
	waf, err = coraza.NewWAF(coraza.NewWAFConfig().
		WithDirectives(`
			# Basic Coraza configuration
			SecRuleEngine On
			SecRequestBodyAccess On
			SecResponseBodyAccess On
			SecRule REQUEST_URI "@contains /admin" "id:1,phase:1,deny,status:403,msg:'Admin access denied'"
		`))
	if err != nil {
		log.Fatalf("Error initializing Coraza: %v", err)
	}
}

func wafHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tx := waf.NewTransaction()
		defer func() {
			if tx.IsInterrupted() {
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprintln(w, "403 Forbidden - Request blocked by WAF")
				return
			}
			tx.ProcessLogging()
			if err := tx.Close(); err != nil {
				log.Printf("Error closing transaction: %v", err)
			}
		}()

		if it, err := tx.ProcessRequest(r); err != nil {
			log.Printf("Error processing request: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		} else if it != nil {
			return // Request was interrupted, response already sent
		}

		next.ServeHTTP(w, r)
	})
}

func main() {
	backendURL, err := url.Parse("http://localhost:8089") // Change this to your backend service URL
	if err != nil {
		log.Fatalf("Error parsing backend URL: %v", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(backendURL)
	http.Handle("/", wafHandler(proxy))

	log.Println("Starting WAF proxy on :8000...")
	if err := http.ListenAndServe(":8000", nil); err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
}
