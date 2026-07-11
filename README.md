# RedKing
RedKing is a simple tool for redirecting web requests.
It was created to help identify and exploit SSRF vulnerabilities similar to these:
 * [CVE-2021-21311](https://github.com/advisories/GHSA-x5r2-hj5c-8jx6)
 * [CVE-2021-21311 Writeup](https://github.com/vrana/adminer/files/5957311/Adminer.SSRF.pdf)
 * [Gitlab SSRF redirect vulnerability](https://gitlab.com/gitlab-org/gitlab-foss/-/issues/54649)

> Use RedKing only against systems you are authorized to test.

## What's New

* **Rotate mode** (`-mode rotate`) — read a file of hosts and hand out a different target on each request, walking the list in order (or forever with `-loop`).
* **Antibot mode** (`-mode antibot`) — gate a single real `-url` behind the same secret the rotate gate uses, but instead of *dropping* requests that fail the gate, redirect them to a harmless **`-decoy`** URL (default: a rickroll). Secret-carrying requests get the real `-url`; bots, scanners, and skids get the decoy, so a passing crawler just sees a boring open-redirect and nothing about the real target is revealed.
* **Multi-location secret gate** — the gate (shared by rotate and antibot) only fires for requests carrying a shared secret, which can ride in the **User-Agent**, **any request header** (`allheaders`), a **`?rk=` query param**, the **`X-Red-King` header**, or the **URL path**. Configure the accepted locations with `-gatein`. This keeps crawlers, preview bots, and scanners from draining your host list, while still working through a server-side fetcher that won't forward a custom header.
* **Auto-generated secret** — if you don't pass `-secret`, RedKing generates a `crypto/rand` token at startup and prints ready-to-use examples for each enabled location.
* **Secret stripping** — wherever the secret is found, it's removed from the request before RedKing logs or acts on it (the User-Agent is tidied back to its real value).
* **`-debug` request dump** — on an ignored (rotate) or decoyed (antibot) request, print the full request line, the expected secret, and every header so you can see exactly what the fetcher sent and where (if anywhere) your secret arrived.
* **`-loop` with wrap-around logging** — cycle through the list forever and see each wrap (pass number, position, running total) in verbose (`-v`) output.
* **`-nogate`** — disable the gate entirely and treat every request as authorized.

> **⚠️ Heads up: some fetchers strip your secret.** Many server-side fetchers (e.g. link-preview / URL-extraction backends) send their *own* `User-Agent` and headers when they fetch your URL, and forward **only the path and query** of the URL you injected — so `header`, `ua`, and even `allheaders` may never see your secret. If the gate isn't firing, run RedKing with **`-debug`** and read the dumped headers on the ignored/decoyed request: it shows the exact `User-Agent`, every header, and the secret RedKing is expecting, so you can tell whether your secret arrived and in what field. If it's not in any header, use the **`query`** (`?rk=<secret>`) or **`path`** (`/<secret>/...`) channel instead — those ride inside the URL and survive the fetch.

## How to Use it
Run RedKing with the `-h` flag to see available options and formats.

```
./RedKing -h
Usage of ./RedKing:
  -debug
    	Debug: on an ignored/decoyed gated request, dump the full request line, expected secret, and all headers so you can see where (if anywhere) the secret arrived
  -decoy string
    	Where to send requests that fail the gate (bots/scanners/skids). Defaults to a rickroll; set this to send them to any other endpoint (antibot mode) (default "https://www.youtube.com/watch?v=dQw4w9WgXcQ")
  -gatein string
    	Comma-separated list of locations to accept the secret from, tried in order. Valid: ua, allheaders, query, header, path (rotate/antibot modes) (default "ua,query,header,path")
  -header string
    	Header name checked for the secret. HTTP header names are case-insensitive; the canonical form (e.g. X-Red-King) avoids proxies like Burp rewriting the casing (rotate/antibot modes) (default "X-Red-King")
  -hostfile string
    	Path to a file of hostnames/URLs to rotate through, one per line (rotate mode)
  -loop
    	Cycle back to the start of the list when hosts are exhausted instead of stopping (rotate mode)
  -mode string
    	The mode RedKing should execute in. Select from:
    	single - redirect to a single URL
    	portscan - create a series of redirects at localhost/1,localhost/2,...
    		Each number will redirect to a different port on the target host.
    		The built in port scan ports are: 22,80,443,445,3389,8000,8080
    	rotate - read -hostfile and redirect each request to the next host in the
    		list. Gate with -header/-secret so only requests carrying the secret header
    		rotate (keeps bots from consuming the list). Add -loop to cycle forever.
    	antibot - gate a single -url like rotate does, but send requests that fail
    		the gate to a harmless -decoy URL (default: a rickroll) instead of dropping
    		them. Secret-carrying requests get -url; bots/scanners/skids get -decoy.
    	 (default "single")
  -nogate
    	Disable the gate and treat every request as authorized (rotate/antibot modes)
  -p int
    	The port used to host the redirect server (default 8080)
  -param string
    	Query parameter name checked for the secret, e.g. ?rk=<secret> (rotate/antibot modes) (default "rk")
  -r int
    	Redirect status code - suggested 301, 302, or 307 (default 302)
  -secret string
    	Secret value that opens the gate. If empty, a secure random secret is generated and printed at startup (rotate/antibot modes)
  -url string
    	The URL used for redirects (single/portscan/antibot modes; in antibot this is the REAL target)
  -v	Verbose
```

## Quickstart
```
./RedKing -url http://test.com


______         _   _   ___
| ___ \       | | | | / (_)
| |_/ /___  __| | | |/ / _ _ __   __ _
|    // _ \/ _' | |    \| | '_ \ / _' |
| |\ \  __/ (_| | | |\  \ | | | | (_| |
\_| \_\___|\__,_| \_| \_/_|_| |_|\__, |
                                  __/ |
                                 |___/


Mode: single
URL: http://test.com
Port: :8080

Starting server on localhost:8080
2021/05/15 21:17:04 Request from 127.0.0.1:12134
```

By default, RedKing opens a server on localhost:8080 and redirects all requests that hit it to the specified url.

### Single Mode
Single mode simply allows you to redirect all traffic to one specific host and path. See the example above for simple usage.

### Portscan Mode

**Note:** This mode is really designed to be used in conjunction with a tool like Burp's Intruder utility or something that will allow you to quickly
trigger requests and then grep through the output.

Portscan mode is designed to allow you to "scan" an internal IP for open ports.
By default it will create a redirect to allow you to test the following ports: 22, 80, 443, 445, 3389, 8000, 8080 \
It will create a series of redirects on your localhost, each of which corresponds to a specific port on the target server.
e.g. \
localhost:8080/0 -> Redirect To -> http://test.com:22 \
localhost:8080/1 -> Redirect To -> http://test.com:80 \
localhost:8080/2 -> Redirect To -> http://test.com:443

Depending on the specifics of the SSRF vulnerability you are exploiting, you may be able to glean information about running processes, or even access 
internal web pages and dump sensitive information. (e.g. the AWS metadata service)

Below is an example portscan mode and bash loop to demonstrate it.


**RedKing Output**
```
./RedKing -url http://test.com -mode portscan


______         _   _   ___
| ___ \       | | | | / (_)
| |_/ /___  __| | | |/ / _ _ __   __ _
|    // _ \/ _' | |    \| | '_ \ / _' |
| |\ \  __/ (_| | | |\  \ | | | | (_| |
\_| \_\___|\__,_| \_| \_/_|_| |_|\__, |
                                  __/ |
                                 |___/


Mode: portscan
URL: http://test.com
Port: :8080

Starting server on localhost:8080
Redirection from 127.0.0.1:13177 to http://test.com:22
Redirection from 127.0.0.1:13180 to http://test.com:80
Redirection from 127.0.0.1:13184 to http://test.com:443
Redirection from 127.0.0.1:13187 to http://test.com:445
Redirection from 127.0.0.1:13189 to http://test.com:3389
Redirection from 127.0.0.1:13192 to http://test.com:8000
Redirection from 127.0.0.1:13195 to http://test.com:8080
```

**TestScript Output**
```
for endpoint in {0..6}; do echo "Connecting to localhost:8080/$endpoint"; curl --retry 0 --connect-timeout 1  -L localhost:8080/$endpoint -Ss | head -5; echo ; done
Connecting to localhost:8080/0
curl: (28) Connection timed out after 1000 milliseconds

Connecting to localhost:8080/1
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">
<meta http-equiv="Content-Script-Type" content="text/javascript">

Connecting to localhost:8080/2
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>400 Bad Request - DOSarrest Internet Security</title>
curl: (23) Failed writing body (0 != 740)

Connecting to localhost:8080/3
curl: (28) Connection timed out after 1001 milliseconds

Connecting to localhost:8080/4
curl: (28) Connection timed out after 1000 milliseconds

Connecting to localhost:8080/5
curl: (28) Connection timed out after 1000 milliseconds

Connecting to localhost:8080/6
curl: (28) Connection timed out after 1000 milliseconds
```

Notice that for endpoints 0,3,4,5,and 6 the connection timed out. This indicates that there is likely _not_ a service running on those ports.

### Rotate Mode

Rotate mode reads a file of hostnames/URLs and hands out a different one on each request. The first request is redirected to the first host, the next request
gets the second host, and so on until the list is exhausted (or forever, with `-loop`). This is useful when a single SSRF trigger point should walk through a
series of targets without editing the config between requests.

#### The gate — and why it lives in several places

To keep crawlers, link-preview bots, and scanners from silently consuming your host list, rotation is gated behind a shared secret. The wrinkle in a real
SSRF: the server that fetches your RedKing URL (a link-preview or extraction backend, say) makes its **own** outbound request and will **not** forward a custom
request header you set on your request to *it*. A header-only gate would therefore reject the very requests you want to redirect.

So RedKing accepts the secret from any location you enable with `-gatein` (default `ua,query,header,path`), tried in that order:

| Location | How to supply it | Notes |
| --- | --- | --- |
| `query` | Inject a URL with `?rk=<secret>` (name set by `-param`) | **Most reliable through a fetcher** — rides inside the URL, which the fetcher preserves. |
| `path` | Inject a URL whose first path segment is the secret: `/<secret>/anything` | Also rides in the URL, but may be normalized/rejected by some fetchers or WAFs. |
| `ua` | Put the secret in your app `User-Agent`, e.g. `...bldTimestamp/1782446400000; <secret>)` | Works only if the fetcher forwards the caller's UA — many send their own. |
| `allheaders` | Any request header value contains the secret | Catches fetchers that relay the secret in a non-standard header (e.g. `X-Yahoo-Rmf-User-Agent`). Substring-scans every header. |
| `header` | Send `X-Red-King: <secret>` | Direct `curl`/Burp testing only; won't survive a fetcher. |

**If rotation isn't firing, run with `-debug`.** On every ignored request RedKing will dump the request line, the secret it's *expecting*, the `User-Agent`, and
every header it received — so you can see exactly what the fetcher sent and whether your secret arrived at all. In practice, server-side fetchers often strip the
UA and headers and forward only the URL, so **`query` and `path` are the channels that survive**; reserve `ua`/`header` for clients you control directly.

Whichever location carries the secret is **stripped** from the request before RedKing logs or acts on it — the `User-Agent` is tidied back to its real value, the
`rk` param is dropped, the header is deleted, or the path segment is removed. (This only affects RedKing's own view; because RedKing issues a `Location` redirect
rather than proxying, it cannot scrub the secret from what the client sends onward — so treat the secret as disposable per engagement.)

If you don't provide `-secret`, RedKing generates a secure random token (`crypto/rand`, 32 bytes, hex) and prints it plus per-location examples at startup. Use
`-nogate` to drop the gate entirely (rotate for every request), or narrow the accepted locations, e.g. `-gatein query,path` or `-gatein ua,query`.

**Flags** (rotate mode) \
`-hostfile` — file of hosts, one per line (required) \
`-secret` — secret that opens the gate; auto-generated if empty \
`-gatein` — locations to accept the secret from, in order (valid: `ua, allheaders, query, header, path`; default `ua,query,header,path`) \
`-header` — header name to check (default `X-Red-King`) \
`-param` — query parameter name to check (default `rk`) \
`-loop` — cycle back to the top of the list instead of stopping once hosts run out \
`-nogate` — disable the gate and rotate for every request \
`-debug` — on an ignored request, dump the full request line, expected secret, and all headers (diagnose whether/where your secret arrived)

**Hostfile format** \
One host per line. Blank lines and lines beginning with `#` are ignored. A line without a scheme has `https://` prepended automatically, so both of the
following are valid:

```
# targets.txt
hostx.com
https://hosty.com/some/path
hostz.com
```

**RedKing Output**
```
./RedKing -mode rotate -hostfile targets.txt -v


______         _   _   ___
| ___ \       | | | | / (_)
| |_/ /___  __| | | |/ / _ _ __   __ _
|    // _ \/ _' | |    \| | '_ \ / _' |
| |\ \  __/ (_| | | |\  \ | | | | (_| |
\_| \_\___|\__,_| \_| \_/_|_| |_|\__, |
                                  __/ |
                                 |___/


Mode: rotate
Hostfile: targets.txt (3 hosts)
Gate: secret accepted in: ua, query, header, path
Loop: false
Port: :8080

Secret: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08

How to supply it (any enabled location works):
  ua     append to your app User-Agent, inside the parens:
           "...bldTimestamp/1782446400000; 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08)"
  query  inject a URL with the param:
           http://<your-host>/anything?rk=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
  header direct testing only (fetchers won't forward it):
           curl -H "X-Red-King: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" http://localhost:8080/
  path   inject a URL whose path starts with the secret:
           http://<your-host>/9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08/anything

Starting server on localhost:8080
2026/07/11 19:31:37 REDIRECTED 72.30.14.65:55600 -> https://hostx.com  (list item 1/3, pass #1, 1 served total, gate: ua)
2026/07/11 19:31:40 REDIRECTED 72.30.14.17:39844 -> https://hosty.com/some/path  (list item 2/3, pass #1, 2 served total, gate: ua)
2026/07/11 19:31:44 REDIRECTED 72.30.14.20:33888 -> https://hostz.com  (list item 3/3, pass #1, 3 served total, gate: ua)
2026/07/11 19:31:48 Host list exhausted after 3 redirect(s) - request from 72.30.14.64:58540 not redirected
```

A request that carries no valid secret in any enabled location is ignored (`404`) and never advances the list:

```
2026/07/11 19:31:25 Ignored request from 72.30.14.20:33888 (no valid secret in ua/query/header/path)
```

Add **`-debug`** to see *why* it was ignored — the full request as RedKing received it, including the secret it expected and every header, so you can tell whether
your secret arrived and in which field:

```
2026/07/11 20:01:23 Ignored request from 72.30.14.17:34238 (no valid secret in ua/query/header/path)
2026/07/11 20:01:23   GET /bananas
2026/07/11 20:01:23   expecting secret: baf1edc1b696cdf1d51ebe289190dd664bb7f67d2c65b52b6525dcc87b8e6868
2026/07/11 20:01:23   User-Agent: "Mozilla/5.0 (compatible; Yahoo Link Preview; https://help.yahoo.com/kb/mail/yahoo-link-preview-SLN23615.html)"
2026/07/11 20:01:23   header Accept: */*
2026/07/11 20:01:23   header Accept-Encoding: gzip
2026/07/11 20:01:23   header User-Agent: Mozilla/5.0 (compatible; Yahoo Link Preview; ...)
```

Here the fetcher sent its **own** User-Agent and no secret anywhere in the request — so `ua`/`header` can't work, and the fix is to inject the secret via
`query` (`?rk=<secret>`) or `path`, which the fetcher preserves.

**TestScript Output**
```
# Grab the secret RedKing printed at startup:
SECRET=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08

# Header channel (direct testing):
for i in {1..4}; do curl -s -o /dev/null -w "%{http_code} -> %{redirect_url}\n" -H "X-Red-King: $SECRET" localhost:8080/; done
302 -> https://hostx.com
302 -> https://hosty.com/some/path
302 -> https://hostz.com
503 ->

# Query channel (useful for GET SSRF) - same secret, no header needed:
curl -s -o /dev/null -w "%{http_code} -> %{redirect_url}\n" "localhost:8080/anything?rk=$SECRET"

# No secret anywhere -> ignored, list untouched:
curl -s -o /dev/null -w "%{http_code}\n" localhost:8080/
404
```

Once the list is exhausted, further requests return `503`. (The server keeps state, so the runs above assume a freshly started RedKing — or use `-loop`.)

**Loop mode** \
Add `-loop` to cycle through the list forever instead of stopping. In verbose (`-v`) mode each wrap-around is logged so you can see when it returns to the
first host:

```
2026/07/11 19:31:04 REDIRECTED 72.30.14.65:55600 -> https://hostx.com  (list item 1/3, pass #1, 1 served total, gate: ua)
2026/07/11 19:31:06 REDIRECTED 72.30.14.17:39844 -> https://hosty.com/some/path  (list item 2/3, pass #1, 2 served total, gate: ua)
2026/07/11 19:31:09 REDIRECTED 72.30.14.20:33888 -> https://hostz.com  (list item 3/3, pass #1, 3 served total, gate: ua)
2026/07/11 19:31:12 Rotated back to the first host - starting pass #2 over 3 host(s) (3 redirect(s) served so far)
2026/07/11 19:31:12 REDIRECTED 72.30.14.64:58540 -> https://hostx.com  (list item 1/3, pass #2, 4 served total, gate: ua)
```

**Note:** the secret rides in plaintext (whichever location you use) and, over plain HTTP, is replayable by anyone who can observe the traffic. Use a fresh
secret per engagement, and run RedKing behind TLS (or a TLS-terminating proxy) where it matters.

### Antibot Mode

Antibot mode redirects a **single** real target (`-url`) but puts it behind the exact same secret gate that rotate mode uses. The difference is what happens to
requests that *don't* carry the secret: instead of being dropped with a `404`, they get a normal-looking redirect to a harmless **decoy** (`-decoy`). So the two
outcomes are:

* **Gate passes** (request carries the secret) → redirect to `-url`, the real target.
* **Gate fails** (bots, scanners, skids, random traffic) → redirect to `-decoy`, which defaults to a rickroll (`https://www.youtube.com/watch?v=dQw4w9WgXcQ`).

Because a failing request gets a clean `302` to a benign, unrelated URL rather than a `404` or `503`, anything scanning your RedKing URL just sees a boring
open-redirect — nothing about the real target is exposed.

The secret, its locations (`-gatein`), the header/param names (`-header`/`-param`), auto-generation, secret-stripping, and `-debug` all behave exactly as they
do in rotate mode; see the [rotate gate section](#the-gate--and-why-it-lives-in-several-places) for the full explanation of *why* the secret can ride in the UA,
query, path, or headers. Antibot mode differs from rotate only in that it serves one fixed real URL (there is no host list) and never returns `404`/`503` — every
request receives a redirect, either to `-url` or to `-decoy`.

`-decoy` is the optional "send bots somewhere else" override: point it at any endpoint you like (a honeypot, a canary, a logging collector, or leave it as the
default rickroll). With `-nogate`, the gate always passes, so every request receives `-url` and the decoy is never used.

**Flags** (antibot mode) \
`-url` — the **real** target that secret-carrying requests are redirected to (required) \
`-decoy` — where everything failing the gate is sent (default: rickroll) \
`-secret` — secret that opens the gate; auto-generated if empty \
`-gatein` — locations to accept the secret from, in order (valid: `ua, allheaders, query, header, path`; default `ua,query,header,path`) \
`-header` — header name to check (default `X-Red-King`) \
`-param` — query parameter name to check (default `rk`) \
`-nogate` — disable the gate; every request gets `-url` (decoy unused) \
`-debug` — on a decoyed request, dump the full request line, expected secret, and all headers

**RedKing Output**
```
./RedKing -mode antibot -url https://real-target.internal/admin -v


______         _   _   ___
| ___ \       | | | | / (_)
| |_/ /___  __| | | |/ / _ _ __   __ _
|    // _ \/ _' | |    \| | '_ \ / _' |
| |\ \  __/ (_| | | |\  \ | | | | (_| |
\_| \_\___|\__,_| \_| \_/_|_| |_|\__, |
                                  __/ |
                                 |___/


Mode: antibot
Real URL: https://real-target.internal/admin
Decoy URL: https://www.youtube.com/watch?v=dQw4w9WgXcQ
Gate: secret accepted in: ua, query, header, path
Port: :8080

Secret: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08

How to supply it (any enabled location works):
  ua     append to your app User-Agent, inside the parens:
           "...bldTimestamp/1782446400000; 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08)"
  query  inject a URL with the param:
           http://<your-host>/anything?rk=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
  header direct testing only (fetchers won't forward it):
           curl -H "X-Red-King: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" http://localhost:8080/
  path   inject a URL whose path starts with the secret:
           http://<your-host>/9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08/anything

Starting server on localhost:8080
2026/07/11 21:07:10 REDIRECTED 72.30.14.65:55600 -> https://real-target.internal/admin  (real target, gate: query)
2026/07/11 21:07:18 DECOY 72.30.14.20:33888 -> https://www.youtube.com/watch?v=dQw4w9WgXcQ  (no valid secret in ua/query/header/path)
```

**TestScript Output**
```
SECRET=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08

# Secret present -> real target:
curl -s -o /dev/null -w "%{http_code} -> %{redirect_url}\n" "localhost:8080/anything?rk=$SECRET"
302 -> https://real-target.internal/admin

# No secret (a "bot") -> decoy:
curl -s -o /dev/null -w "%{http_code} -> %{redirect_url}\n" localhost:8080/
302 -> https://www.youtube.com/watch?v=dQw4w9WgXcQ
```

Send bots to your own endpoint instead of the rickroll with `-decoy`:
```
./RedKing -mode antibot -url https://real-target.internal/admin -decoy https://honeypot.example.com/trap
```

## Docker
To run in docker, run the image and specify command line arguments.
```
docker pull bpsizemore/redking
docker run bpsizemore/redking -h
docker run bpsizemore/redking -url test.com -mode single
```
**https://hub.docker.com/r/bpsizemore/redking**
