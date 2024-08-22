package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/corazawaf/coraza/v3"
)

var waf coraza.WAF

func initCoraza() error {
	config := coraza.NewWAFConfig().WithDirectives(`
		SecRuleEngine On
		SecRule REQUEST_URI "@contains malicious" "id:1,phase:1,deny,status:403,log,msg:'Potential malicious activity detected'"
	`)

	var err error
	waf, err = coraza.NewWAF(config)
	return err
}

func wafMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tx := waf.NewTransaction()
		defer tx.Close()

		// 简化的请求处理
		tx.ProcessURI(r.URL.String(), r.Method, r.Proto)
		for k, v := range r.Header {
			tx.AddRequestHeader(k, v[0])
		}
		tx.ProcessRequestHeaders()

		if tx.IsInterrupted() {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintln(w, "Request blocked by WAF")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func main() {
	if err := initCoraza(); err != nil {
		log.Fatalf("Failed to initialize Coraza: %v", err)
	}

	backendURL, err := url.Parse("http://localhost:8080") // 修改为您的后端服务 URL
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
