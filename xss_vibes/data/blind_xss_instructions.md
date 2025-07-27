# Blind XSS Payloads Usage Instructions

## Setup Required

Before using Blind XSS payloads, you need to:

1. **Set up your callback domain/service:**
   - Replace `YOUR_BLIND_XSS_DOMAIN` with your actual domain
   - Replace `YOUR_ID` with your unique identifier

2. **Popular Blind XSS services:**
   - XSS Hunter (free): https://xsshunter.com
   - Burp Collaborator (paid)
   - Custom callback server

## Payload Types

### 1. Default Vector
- Simple and effective for most cases
- Good for basic reflection points

### 2. CSP Bypass Vector  
- Bypasses basic Content Security Policy
- Uses `<base>` tag for domain redirection

### 3. Short Polyglot
- Works in multiple contexts (HTML, JS)
- Balanced size and effectiveness

### 4. Full Polyglot (RECOMMENDED)
- Works in 20+ different XSS contexts
- Most comprehensive but larger payload

## Usage in XSS Vibes

```bash
# Scan with Blind XSS payloads
python -m xss_vibes scan --enhanced-payloads --payload-category blind_xss https://target.com

# List Blind XSS payloads
python -m xss_vibes pattern-list --type blind_xss
```

## Important Security Notes

⚠️ **NEVER commit files containing your real domain/ID to version control!**
⚠️ **Always sanitize payloads before sharing**
⚠️ **Only test on systems you own or have permission to test**
