// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

// Command ares-practice is a small, deliberately weak web app for local
// development and demos. It gives Ares something safe to test: scripts/dev.sh
// starts it on the loopback interface and the seeded demo engagement is scoped
// to it alone, so no check ever leaves the developer's machine.
//
// Every weakness here is simulated. The "exposed" files are canned text with no
// real secrets, the template "engine" only multiplies two numbers, and the
// path-traversal endpoint returns a fixed fake passwd line without ever reading
// the disk. It refuses to listen on anything but a loopback address.
package main

import (
	"flag"
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8089", "loopback address to listen on")
	flag.Parse()

	host, _, err := net.SplitHostPort(*addr)
	if err != nil {
		log.Fatalf("practice target: bad -addr %q: %v", *addr, err)
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		log.Fatalf("practice target: refusing to listen on %q; it is deliberately weak and must stay on loopback", *addr)
	}

	srv := &http.Server{
		Addr:              *addr,
		Handler:           routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("practice target (deliberately weak, loopback only) on http://%s", *addr)
	log.Fatal(srv.ListenAndServe())
}

// routes wires the simulated weaknesses. Each handler names the Ares check it
// exists to trip.
func routes() http.Handler {
	mux := http.NewServeMux()

	// Home page: no security headers and a wildcard CORS policy
	// (webcheck: missing-* headers, cors-wildcard-origin; httpprobe).
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		page(w, "Northwind Coffee (practice target)", `
<p>This is a <strong>deliberately weak</strong> practice site for Ares. It runs only on your machine.</p>
<ul>
  <li><a href="/search?q=coffee">Search the menu</a></li>
  <li><a href="/greet?name=guest">Get a greeting</a></li>
  <li><a href="/download?file=menu.txt">Download the menu</a></li>
  <li><a href="/go?next=/">Continue</a></li>
</ul>`)
	})

	// Reflected input: the query is echoed without encoding (injectprobe).
	mux.HandleFunc("GET /search", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		page(w, "Search", "<p>No drinks matched <b>"+q+"</b>.</p>")
	})

	// Template injection, simulated: only "{{a*b}}" is evaluated, as arithmetic
	// (sstiprobe). Anything else is shown escaped.
	mux.HandleFunc("GET /greet", func(w http.ResponseWriter, r *http.Request) {
		name := html.EscapeString(r.URL.Query().Get("name"))
		name = jinjaMul.ReplaceAllStringFunc(name, func(m string) string {
			p := jinjaMul.FindStringSubmatch(m)
			a, _ := strconv.ParseInt(p[1], 10, 64)
			b, _ := strconv.ParseInt(p[2], 10, 64)
			return strconv.FormatInt(a*b, 10)
		})
		page(w, "Greeting", "<p>Hello, "+name+"!</p>")
	})

	// Open redirect: any destination is accepted (redirectprobe). The Location
	// is only sent back; this server never follows it.
	mux.HandleFunc("GET /go", func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		if next == "" {
			next = "/"
		}
		w.Header().Set("Location", next)
		w.WriteHeader(http.StatusFound)
	})

	// Path traversal, simulated: a "../" request for /etc/passwd gets a fixed,
	// fake line. The disk is never read (traversalprobe).
	mux.HandleFunc("GET /download", func(w http.ResponseWriter, r *http.Request) {
		f := r.URL.Query().Get("file")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if strings.Contains(f, "..") && strings.Contains(f, "etc/passwd") {
			fmt.Fprint(w, "root:x:0:0:root:/root:/bin/sh\npractice:x:1000:1000:Fake account:/home/practice:/bin/sh\n")
			return
		}
		fmt.Fprint(w, "Espresso 2.50\nFlat white 3.20\nCold brew 3.80\n")
	})

	// "Exposed" files with canned, fake content (webcheck exposure rules).
	canned := map[string]struct{ ctype, body string }{
		"/.env":         {"text/plain", "APP_ENV=practice\nDB_HOST=127.0.0.1\nDB_PASSWORD=not-a-real-secret\n"},
		"/.git/config":  {"text/plain", "[core]\n\trepositoryformatversion = 0\n\tbare = false\n"},
		"/metrics":      {"text/plain", "# HELP practice_requests_total Requests served.\n# TYPE practice_requests_total counter\npractice_requests_total 42\n"},
		"/openapi.json": {"application/json", `{"openapi":"3.0.0","info":{"title":"Northwind practice API","version":"1.0"},"paths":{}}`},
	}
	for path, c := range canned {
		mux.HandleFunc("GET "+path, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", c.ctype)
			fmt.Fprint(w, c.body)
		})
	}

	return weakHeaders(mux)
}

var jinjaMul = regexp.MustCompile(`\{\{\s*(\d{1,9})\s*\*\s*(\d{1,9})\s*\}\}`)

// weakHeaders sets the headers that make the site look careless: a version
// banner and a wildcard CORS policy, with none of the protective headers.
func weakHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "NorthwindPractice/1.0")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		next.ServeHTTP(w, r)
	})
}

func page(w http.ResponseWriter, title, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<!doctype html><html><head><title>%s</title></head><body><h1>%s</h1>%s</body></html>",
		html.EscapeString(title), html.EscapeString(title), body)
}
