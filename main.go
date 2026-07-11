package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
)

var Config struct {
	asciiart       string
	redirectStatus int
	verbosity      int
	debug          bool
	redirectUrl    string
	redirectHost   string
	port           int
	httpPort       string
	mode           string
	validModes     []string
	scanPorts      []string
	// rotate mode
	hostFile        string
	rotateHosts     []string
	rotateHeader    string
	rotateParam     string   // query param name carrying the secret (e.g. rk)
	rotateGateIn    []string // accepted secret locations: ua, query, header, path
	rotateSecret    string
	rotateLoop      bool
	rotateOpen      bool // -nogate: rotate for everyone, no secret required
	rotateGenerated bool // secret was auto-generated
	rotateIndex     int  // next host to hand out
	rotateCycles    int  // completed passes over the full list
	rotateServed    int  // total redirects served
}

// rotateMu guards the rotate counters, which are mutated on every request.
var rotateMu sync.Mutex

func ValidateUrl(urlPtr *string) error {
	u, err := url.Parse(*urlPtr)
	if err != nil {
		return err
	}
	if u.Scheme == "" || u.Host == "" {
		return errors.New("URL is invalid. Please supply a URL in the format: https://test.com/some/path")
	}
	return nil
}

func ValidateMode(modePtr *string) error {
	for _, mode := range Config.validModes {
		if strings.ToLower(*modePtr) == strings.ToLower(mode) {
			return nil
		}
	}
	return errors.New("Invalid mode selected. Please choose one of the valid modes") // + string(Config.validModes))
}

func ExtractHostFromUrl(urlPtr *string) string {
	u, err := url.Parse(*urlPtr)
	if err != nil {
		panic(err)
	}
	return u.Host
}

// GenerateSecret returns a cryptographically secure random token, hex encoded.
func GenerateSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// LoadHosts reads a file of hostnames/URLs (one per line) and normalizes them.
// Blank lines and lines starting with '#' are ignored. Lines without a scheme
// get https:// prepended so they are valid redirect targets.
func LoadHosts(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var hosts []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.Contains(line, "://") {
			line = "https://" + line
		}
		hosts = append(hosts, line)
	}
	if len(hosts) == 0 {
		return nil, errors.New("host file contained no valid hosts")
	}
	return hosts, nil
}

func handleRedirect(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "You are being redirected...")
}

func RedirectToSite(url string) {
	// Static Redirect to a single site.
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, url, Config.redirectStatus)
		log.Printf("Request from %s", r.RemoteAddr)
	})
}

func RedirectToSiteWithTarget(target string, url string) {
	// Static Redirect to a single site.
	http.HandleFunc(target, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, url, Config.redirectStatus)
		fmt.Printf("Redirection from %s to %s\n", r.RemoteAddr, url)
	})
}

func RedirectPortScan(url string) {
	// Used to do a simple "port scan" against a host via redirect.
	// Use this in conjunction with Burp or an automated script for fastest results.
	// Defaults to testing a small number of important ports.
	for i, port := range Config.scanPorts {
		if Config.verbosity > 0 {
			fmt.Println("adding handler for port ", port, i)
		}
		//Setup a bunch of handlers like /1, /2, /3 which each redirect to a different port on one host
		RedirectToSiteWithTarget("/"+strconv.Itoa(i), url+":"+port)
	}
}

// gateResult reports whether a rotate request carries the secret and, if so,
// where it was found. In an SSRF the server that fetches RedKing (e.g. a
// link-preview backend) makes its own request and does NOT forward your custom
// header - but it often preserves the User-Agent, the URL path, and the query
// string of the URL you injected. So the secret can ride in any of several
// places; RedKing accepts whichever locations -gatein allows. Order of the
// returned "via" follows Config.rotateGateIn.
//
//	ua      set your app User-Agent to "...realUA...; <secret>)"  (default)
//	query   inject  url=http://your-host/path?rk=<secret>          (GET)
//	header  send    X-Red-King: <secret>                           (direct testing)
//	path    inject  url=http://your-host/<secret>/anything
func gateResult(r *http.Request) (allowed bool, via string) {
	if Config.rotateOpen {
		return true, "nogate"
	}
	if Config.rotateSecret == "" {
		return false, ""
	}
	for _, loc := range Config.rotateGateIn {
		switch loc {
		case "header":
			if r.Header.Get(Config.rotateHeader) == Config.rotateSecret {
				return true, "header"
			}
		case "query":
			if r.URL.Query().Get(Config.rotateParam) == Config.rotateSecret {
				return true, "query"
			}
		case "ua":
			if strings.Contains(r.Header.Get("User-Agent"), Config.rotateSecret) {
				return true, "ua"
			}
		case "allheaders":
			// Scan every request header value. Useful when a fetcher relays
			// your app UA (or the secret) in a non-standard header such as
			// X-Yahoo-Rmf-User-Agent instead of User-Agent.
			for _, vals := range r.Header {
				for _, v := range vals {
					if strings.Contains(v, Config.rotateSecret) {
						return true, "allheaders"
					}
				}
			}
		case "path":
			firstSeg := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)[0]
			if firstSeg == Config.rotateSecret {
				return true, "path"
			}
		}
	}
	return false, ""
}

// stripSecret removes the secret from wherever gateResult found it, so RedKing
// doesn't echo it in its own logs. For "ua" it also tidies up the leftover
// separators, restoring the original User-Agent. NOTE: RedKing only issues a
// Location redirect; it does not proxy the follow-up request, so this only
// affects RedKing's own view - it can't scrub the secret from what the client
// sends onward.
func stripSecret(r *http.Request, via string) {
	switch via {
	case "header":
		r.Header.Del(Config.rotateHeader)
	case "query":
		q := r.URL.Query()
		q.Del(Config.rotateParam)
		r.URL.RawQuery = q.Encode()
	case "ua":
		ua := r.Header.Get("User-Agent")
		s := Config.rotateSecret
		// Peel off common ways the token gets appended, longest first.
		for _, pat := range []string{"; " + s, ";" + s, " " + s, s} {
			ua = strings.ReplaceAll(ua, pat, "")
		}
		r.Header.Set("User-Agent", ua)
	case "path":
		parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)
		if len(parts) == 2 {
			r.URL.Path = "/" + parts[1]
		} else {
			r.URL.Path = "/"
		}
	case "allheaders":
		s := Config.rotateSecret
		for name, vals := range r.Header {
			for i, v := range vals {
				if strings.Contains(v, s) {
					for _, pat := range []string{"; " + s, ";" + s, " " + s, s} {
						v = strings.ReplaceAll(v, pat, "")
					}
					r.Header[name][i] = v
				}
			}
		}
	}
}

// RedirectRotate hands out one host from the list per request. It walks the
// list in order; with -loop it wraps back to the first host (logging the wrap
// in verbose mode), otherwise it returns 503 once the list is exhausted.
//
// Unless -nogate is set, rotation is gated behind the shared secret, which may
// be supplied in any location -gatein allows (User-Agent, ?rk= query param,
// header, or path segment). Requests failing the gate get a plain 404 and never
// advance the list. See gateResult for why UA/query/path exist (SSRF).
func RedirectRotate() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Gate check happens before taking the lock so failing requests
		// never touch the shared rotate state.
		allowed, via := gateResult(r)
		if !allowed {
			http.NotFound(w, r)
			if Config.verbosity > 0 || Config.debug {
				log.Printf("Ignored request from %s (no valid secret in %s)", r.RemoteAddr, strings.Join(Config.rotateGateIn, "/"))
			}
			if Config.debug {
				// Full dump so you can see exactly what the fetcher sent and
				// where (if anywhere) the secret landed. Compare "expecting"
				// against the header values below.
				log.Printf("  %s %s", r.Method, r.URL.RequestURI())
				log.Printf("  expecting secret: %s", Config.rotateSecret)
				log.Printf("  User-Agent: %q", r.Header.Get("User-Agent"))
				for name, vals := range r.Header {
					for _, v := range vals {
						log.Printf("  header %s: %s", name, v)
					}
				}
			}
			return
		}

		// Remove the secret from wherever it was found so RedKing doesn't echo
		// it in its own logs. NOTE: RedKing only issues a Location redirect, it
		// does not proxy the follow-up request, so this can't scrub the secret
		// from what the client sends onward.
		stripSecret(r, via)

		rotateMu.Lock()
		defer rotateMu.Unlock()

		// Reached the end of the list.
		if Config.rotateIndex >= len(Config.rotateHosts) {
			if !Config.rotateLoop {
				http.Error(w, "No more hosts to redirect to.", http.StatusServiceUnavailable)
				log.Printf("Host list exhausted after %d redirect(s) - request from %s not redirected",
					Config.rotateServed, r.RemoteAddr)
				return
			}
			// Loop mode: wrap back around to the first host.
			Config.rotateIndex = 0
			Config.rotateCycles++
			if Config.verbosity > 0 {
				log.Printf("Rotated back to the first host - starting pass #%d over %d host(s) (%d redirect(s) served so far)",
					Config.rotateCycles+1, len(Config.rotateHosts), Config.rotateServed)
			}
		}

		target := Config.rotateHosts[Config.rotateIndex]
		pos := Config.rotateIndex + 1
		Config.rotateIndex++
		Config.rotateServed++

		http.Redirect(w, r, target, Config.redirectStatus)

		if Config.verbosity > 0 {
			log.Printf("REDIRECTED %s -> %s  (list item %d/%d, pass #%d, %d served total, gate: %s)",
				r.RemoteAddr, target, pos, len(Config.rotateHosts), Config.rotateCycles+1, Config.rotateServed, via)
		} else {
			log.Printf("REDIRECTED %s -> %s  (list item %d/%d)",
				r.RemoteAddr, target, pos, len(Config.rotateHosts))
		}
	})
}

func main() {
	// Setup default config - not sure where this should go instead
	Config.scanPorts = []string{"22", "80", "443", "445", "3389", "8000", "8080"}
	Config.validModes = []string{"single", "portscan", "rotate"}
	Config.asciiart =
		`
______         _   _   ___
| ___ \       | | | | / (_)
| |_/ /___  __| | | |/ / _ _ __   __ _
|    // _ \/ _' | |    \| | '_ \ / _' |
| |\ \  __/ (_| | | |\  \ | | | | (_| |
\_| \_\___|\__,_| \_| \_/_|_| |_|\__, |
                                  __/ |
                                 |___/

              Modified by Falasi - credits to bpsizemore
`
	redirectStatusPtr := flag.Int("r", 302, "Redirect status code - suggested 301, 302, or 307")
	verbosityPtr := flag.Bool("v", false, "Verbose")
	debugPtr := flag.Bool("debug", false, "Debug: on an ignored rotate request, dump the full request line, expected secret, and all headers so you can see where (if anywhere) the secret arrived")
	urlPtr := flag.String("url", "", "The URL used for redirects (single/portscan modes)")
	portPtr := flag.Int("p", 8080, "The port used to host the redirect server")
	hostFilePtr := flag.String("hostfile", "", "Path to a file of hostnames/URLs to rotate through, one per line (rotate mode)")
	rotateHeaderPtr := flag.String("header", "X-Red-King", "Header name checked for the secret. HTTP header names are case-insensitive; the canonical form (e.g. X-Red-King) avoids proxies like Burp rewriting the casing (rotate mode)")
	rotateParamPtr := flag.String("param", "rk", "Query parameter name checked for the secret, e.g. ?rk=<secret> (rotate mode)")
	rotateGateInPtr := flag.String("gatein", "ua,query,header,path", "Comma-separated list of locations to accept the secret from, tried in order. Valid: ua, allheaders, query, header, path (rotate mode)")
	rotateSecretPtr := flag.String("secret", "", "Secret value that opens the gate. If empty, a secure random secret is generated and printed at startup (rotate mode)")
	rotateLoopPtr := flag.Bool("loop", false, "Cycle back to the start of the list when hosts are exhausted instead of stopping (rotate mode)")
	rotateNoGatePtr := flag.Bool("nogate", false, "Disable the header gate and rotate for every request (rotate mode)")
	modePtr := flag.String("mode", "single", "The mode RedKing should execute in. Select from:\nsingle - redirect to a single URL\nportscan - create a series of redirects at localhost/1,localhost/2,...\n\tEach number will redirect to a different port on the target host.\n\tThe built in port scan ports are: 22,80,443,445,3389,8000,8080\nrotate - read -hostfile and redirect each request to the next host in the\n\tlist. Gate with -header/-secret so only requests carrying the secret header\n\trotate (keeps bots from consuming the list). Add -loop to cycle forever.\n")
	flag.Parse()

	// Validate mode first so we know which other flags are required.
	mode_err := ValidateMode(modePtr)
	if mode_err != nil {
		log.Fatal(mode_err)
	}
	Config.mode = strings.ToLower(*modePtr)

	Config.redirectStatus = *redirectStatusPtr
	if *verbosityPtr == false {
		Config.verbosity = 0
	} else {
		Config.verbosity = 1
	}
	Config.debug = *debugPtr

	Config.port = *portPtr
	Config.httpPort = ":" + strconv.Itoa(*portPtr)
	Config.rotateHeader = *rotateHeaderPtr
	Config.rotateParam = *rotateParamPtr
	Config.rotateLoop = *rotateLoopPtr
	Config.rotateOpen = *rotateNoGatePtr

	// Parse -gatein into the ordered list of accepted secret locations.
	validGate := map[string]bool{"ua": true, "allheaders": true, "query": true, "header": true, "path": true}
	for _, loc := range strings.Split(*rotateGateInPtr, ",") {
		loc = strings.ToLower(strings.TrimSpace(loc))
		if loc == "" {
			continue
		}
		if !validGate[loc] {
			log.Fatalf("invalid -gatein value %q (valid: ua, allheaders, query, header, path)", loc)
		}
		Config.rotateGateIn = append(Config.rotateGateIn, loc)
	}
	if !Config.rotateOpen && len(Config.rotateGateIn) == 0 {
		log.Fatal(errors.New("-gatein must list at least one location, or use -nogate"))
	}

	// Mode-specific setup / validation.
	switch Config.mode {
	case "single", "portscan":
		err := ValidateUrl(urlPtr)
		if err != nil {
			log.Fatal(err)
		}
		Config.redirectUrl = *urlPtr
		Config.redirectHost = ExtractHostFromUrl(urlPtr)
	case "rotate":
		if *hostFilePtr == "" {
			log.Fatal(errors.New("rotate mode requires -hostfile pointing to a list of hosts"))
		}
		hosts, err := LoadHosts(*hostFilePtr)
		if err != nil {
			log.Fatal(err)
		}
		Config.hostFile = *hostFilePtr
		Config.rotateHosts = hosts

		// Establish the header secret unless the gate is disabled.
		if !Config.rotateOpen {
			if *rotateSecretPtr != "" {
				Config.rotateSecret = *rotateSecretPtr
			} else {
				secret, err := GenerateSecret()
				if err != nil {
					log.Fatal(err)
				}
				Config.rotateSecret = secret
				Config.rotateGenerated = true
			}
		}
	}

	fmt.Println(Config.asciiart)

	switch Config.mode {
	case "rotate":
		var gate string
		switch {
		case Config.rotateOpen:
			gate = "none (-nogate: every request rotates)"
		default:
			gate = fmt.Sprintf("secret accepted in: %s", strings.Join(Config.rotateGateIn, ", "))
		}
		fmt.Printf("Mode: %s\nHostfile: %s (%d hosts)\nGate: %s\nLoop: %t\nPort: %s\n",
			Config.mode, Config.hostFile, len(Config.rotateHosts), gate, Config.rotateLoop, Config.httpPort)
		if !Config.rotateOpen {
			fmt.Printf("\nSecret: %s\n\nHow to supply it (any enabled location works):\n", Config.rotateSecret)
			for _, loc := range Config.rotateGateIn {
				switch loc {
				case "ua":
					fmt.Printf("  ua     append to your app User-Agent, inside the parens:\n           \"...bldTimestamp/1782446400000; %s)\"\n", Config.rotateSecret)
				case "query":
					fmt.Printf("  query  inject a URL with the param:\n           http://<your-host>/anything?%s=%s\n", Config.rotateParam, Config.rotateSecret)
				case "header":
					fmt.Printf("  header direct testing only (fetchers won't forward it):\n           curl -H \"%s: %s\" http://localhost%s/\n", Config.rotateHeader, Config.rotateSecret, Config.httpPort)
				case "path":
					fmt.Printf("  path   inject a URL whose path starts with the secret:\n           http://<your-host>/%s/anything\n", Config.rotateSecret)
				}
			}
		}
		fmt.Println()
	default:
		fmt.Printf("Mode: %s \nURL: %s\nPort: %s\n\n", Config.mode, Config.redirectUrl, Config.httpPort)
	}

	switch Config.mode {
	case "single":
		RedirectToSite(Config.redirectUrl)
	case "portscan":
		RedirectPortScan(Config.redirectUrl)
	case "rotate":
		RedirectRotate()
	}

	fmt.Printf("Starting server on localhost%s\n", Config.httpPort)
	log.Fatal(http.ListenAndServe(Config.httpPort, nil))
}
