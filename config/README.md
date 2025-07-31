# XSS Vibes V2 - API Configuration
# Store your API keys here (these files are gitignored)

# Fofa Configuration
echo "your-fofa-email@example.com" > config/fofa_email.txt
echo "your-fofa-api-key" > config/fofa_api_key.txt

# Shodan Configuration  
echo "your-shodan-api-key" > config/shodan_api_key.txt

# Or use environment variables:
export FOFA_EMAIL="your-fofa-email@example.com"
export FOFA_KEY="your-fofa-api-key"
export SHODAN_KEY="your-shodan-api-key"

# Example usage with Makefile:
make target-hunt-soa2 FOFA_EMAIL="email@example.com" FOFA_KEY="key" SHODAN_KEY="key"

# Example direct usage:
./tools/fofa-searcher -q 'title="ctrip"' --email email@example.com --key fofa-key
./tools/shodan-searcher -q 'http.title:"admin"' --key shodan-key
./tools/simple-target-hunter -s soa2_discovery --fofa-email email --fofa-key key --shodan-key key
