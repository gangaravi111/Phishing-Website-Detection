import os
import requests
import whois
import urllib.parse
from datetime import datetime

def check_safe_browsing(url):
    """
    Checks a URL against the Google Safe Browsing API.
    Requires SAFE_BROWSING_API_KEY environment variable to be set.
    """
    api_key = os.environ.get('SAFE_BROWSING_API_KEY')
    
    if not api_key:
        return {
            "status": "skipped",
            "message": "API key not configured."
        }
        
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    
    payload = {
        "client": {
            "clientId": "phishield-detection",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
            ]
        }
    }
    
    try:
        response = requests.post(endpoint, json=payload, timeout=5)
        response.raise_for_status()
        data = response.json()
        
        if "matches" in data and len(data["matches"]) > 0:
            threat_type = data["matches"][0].get("threatType", "Unknown Threat")
            return {
                "status": "unsafe",
                "threat_type": threat_type,
                "message": f"Flagged by Google Safe Browsing as {threat_type}"
            }
        else:
            return {
                "status": "safe",
                "message": "No threats found by Google Safe Browsing"
            }
            
    except requests.exceptions.RequestException as e:
        print(f"[WARNING] Google Safe Browsing API error: {e}")
        return {
            "status": "error",
            "message": "Failed to connect to threat intelligence service."
        }

def get_domain_creation_info(url):
    """
    Looks up the WHOIS record for the domain to find its creation date and age.
    """
    try:
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path
        
        if domain.startswith("www."):
            domain = domain[4:]
            
        # Stop execution for obviously invalid domains or raw IPs to save time
        if not domain or domain.replace('.', '').isdigit():
             return {"success": False, "error": "Invalid domain or raw IP address."}
             
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if creation_date:
            # Strip timezone info if it exists to safely subtract from naive datetime.now()
            if creation_date.tzinfo is not None:
                creation_date = creation_date.replace(tzinfo=None)
                
            age_in_days = (datetime.now() - creation_date).days
            return {
                "success": True,
                "domain": domain,
                "creation_date": creation_date.strftime("%Y-%m-%d"),
                "age_in_days": age_in_days,
                "is_suspiciously_new": age_in_days < 30
            }
        
        return {"success": False, "error": "Creation date not found in WHOIS record."}
        
    except Exception as e:
        error_msg = str(e)
        print(f"[WARNING] WHOIS lookup failed: {error_msg}")
        
        # Translate ugly Python errors into user-friendly UI messages
        if "Whois command returned no output" in error_msg or "No match for" in error_msg:
            ui_message = "Domain record not found or is unregistered."
        elif "Timeout" in error_msg:
            ui_message = "WHOIS server timed out checking this domain."
        else:
            ui_message = "Unable to retrieve WHOIS information for this URL."
            
        return {"success": False, "error": ui_message}
