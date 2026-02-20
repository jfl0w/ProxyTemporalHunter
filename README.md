# Reverse Proxy Temporal Analysis
Identify C2 reverse proxies by analyzing the response times to crafted HTTP requests. This threat hunting technique was first discussed by Marcus Hutchins using a Python script in 2017: https://www.malwaretech.com/2017/11/investigating-command-and-control-infrastructure-emotet.html:

"The way this works is it sends two HTTP requests: one which should trigger a 404 error (page not found), followed by one which should trigger a 400 error (invalid request), recording the time taken for each. Both 404 and 400 pages should have similar response times; however, if we’re dealing with a reverse proxy the timing should differ noticeably. The first request will get forwarded to the origin, which will see the page doesn’t exist and return a 404. The second request is invalid so the proxy will not bother to forward it, instead a 400 error will be returned directly. Due to the fact the valid request is forwarded to the origin but the invalid one isn’t, the invalid request will get a response much faster than the valid one, if we’re dealing with a reverse proxy."

## Usage
1. Input a suspicious C2 IP address or use one from the FEODO threat intel feed: https://feodotracker.abuse.ch/blocklist/#iocs
2. (Optional) Specify a port number in the port input box (e.g. 8080). 
You can type the port with or without the colon :8080 or 8080 both work. 
If you already include a port in the host field (e.g. 192.168.1.1:8080), the separate port box takes precedence and overrides it.
4. Click "SCAN" and wait for the timing analysis results.
5. In the example screenshot below, we are using a known Emotet C2 IP address with the port 8080 and can see the valid request took twice as long as the invalid request. 

![proxydetect](https://github.com/user-attachments/assets/e34f29bb-c330-4f84-bea7-cbce07b820e0)

## Caveats
Since this tool runs in a browser, raw TCP socket access isn't available like in the Python code. It uses the fetch API with mode: 'no-cors' instead, which means:

1. CORS won't block the requests, but you won't see response bodies or status codes
2. The timing signal is still measurable via performance.now()
3. Results are best effort. HTTPS targets with HSTS, or servers that close connections immediately, may skew readings
4. This technique may not be the most accurate and you may need to scan several times. It is not meant to be used solely to identify C2 servers running reverse proxies, but rather as a complimentary enrichment tool in your threat hunting process.

This tool will is even more unreliable with URLs because in the browser, you can't send a raw malformed HTTP request the way the Python script does. 
The Python trick works by crafting a packet with "Most:" instead of "Host:" in the headers, which is something something no browser will ever let you do. 
The fetch API always sends a well-formed HTTP request regardless of what you put in the headers object.

So what the app is actually measuring with a URL like "example.com" is:
"Valid" request: GET /aaaaaaaa → gets a 404 from the origin
"Invalid" request: GET /aaaaaaaa with an extra custom header → also gets a 404 from the origin (because the proxy sees a valid-looking request and forwards it anyway)

For accurate results matching the Python script's technique, the app works best when pointing at a raw IP:port running an HTTP server directly, where you're more likely to see a detectable timing difference. For polished production URLs like example.com, the browser's fetch limitations mean the results should be treated as a rough heuristic rather than a reliable proxy signal.

