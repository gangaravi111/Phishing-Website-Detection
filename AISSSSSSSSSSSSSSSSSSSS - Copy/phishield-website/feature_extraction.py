# feature_extraction.py
import re
from urllib.parse import urlparse
import numpy as np

def extract_features(url):
    """
    Extracts 29 key lexical features compatible with the new Phishing Dataset.
    Returns a numpy array of shape (1, 29).
    """
    
    """
    Extracts 48 key lexical features compatible with the new Phishing Dataset.
    Returns a numpy array of shape (1, 48).
    """
    
    features = []
    
    # Pre-calculations
    parsed = urlparse(url)
    hostname = parsed.netloc
    path = parsed.path
    
    # 1. length_url
    features.append(len(url))
    
    # 2. length_hostname
    features.append(len(hostname))
    
    # 3. ip
    ip_pattern = re.compile(r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\/)|'
                            r'((0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\/)'
                            r'(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}')
    features.append(1 if ip_pattern.search(url) else 0)
    
    # 4-23: Char counts
    chars = ['.', '-', '@', '?', '&', '|', '=', '_', '~', '%', '/', '*', ':', ',', ';', '$', ' ']
    for c in chars:
        features.append(url.count(c))
        
    features.append(url.count('www'))
    features.append(url.count('.com'))
    features.append(url.count('//'))
    
    # 24. http_in_path
    features.append(1 if 'http' in path else 0)
    
    # 25. https_token
    features.append(1 if 'https' in parsed.scheme else 0)
    
    # 26. ratio_digits_url
    features.append(sum(c.isdigit() for c in url) / len(url) if len(url) > 0 else 0)
    
    # 27. ratio_digits_host
    features.append(sum(c.isdigit() for c in hostname) / len(hostname) if len(hostname) > 0 else 0)
    
    # 28. port
    try:
        features.append(1 if parsed.port else 0)
    except:
        features.append(0)
    
    # 29. phish_hints (Expanded)
    suspicious_words = ['secure', 'account', 'webscr', 'login', 'ebayisapi', 'signin', 'banking', 'confirm',
                        'update', 'verify', 'user', 'client', 'suspend', 'restrict', 'hold', 'bill', 'pay']
    features.append(sum(1 for word in suspicious_words if word in url.lower()))
    
    # 30. shortening_service
    shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                          r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                          r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                          r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                          r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                          r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                          r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                          r"tr\.im|link\.zip\.net"
    features.append(1 if re.search(shortening_services, url, flags=re.IGNORECASE) else 0)
    
    # 31. nb_subdomains
    features.append(hostname.count('.'))
    
    # 32. prefix_suffix (hyphen in domain)
    features.append(1 if '-' in hostname else 0)
    
    # Word stats
    words_raw = re.split(r'\W+', url)
    words_raw = [w for w in words_raw if w]
    words_host = re.split(r'\W+', hostname)
    words_host = [w for w in words_host if w]
    words_path = re.split(r'\W+', path)
    words_path = [w for w in words_path if w]

    # 33. length_words_raw
    features.append(len(words_raw))
    
    # 34. shortest_word_host
    features.append(min(len(w) for w in words_host) if words_host else 0)
    
    # 35. longest_words_raw
    features.append(max(len(w) for w in words_raw) if words_raw else 0)
    
    # 36. longest_word_host
    features.append(max(len(w) for w in words_host) if words_host else 0)
    
    # 37. avg_words_raw
    features.append(sum(len(w) for w in words_raw) / len(words_raw) if words_raw else 0)
    
    # 38. avg_word_host
    features.append(sum(len(w) for w in words_host) / len(words_host) if words_host else 0)
    
    # 39. char_repeat
    def max_repeat(s):
        if not s: return 0
        max_r = 1
        current_r = 1
        for i in range(1, len(s)):
            if s[i] == s[i-1]:
                current_r += 1
                max_r = max(max_r, current_r)
            else:
                current_r = 1
        return max_r
    features.append(max_repeat(url))
    
    # 40. tld_in_path
    tlds = ['com', 'net', 'org', 'info', 'biz', 'gov', 'edu']
    tld_in_p = 0
    for tld in tlds:
        if f'.{tld}/' in path or f'.{tld}' in path:
            tld_in_p = 1
            break
    features.append(tld_in_p)
    
    # 41. tld_in_subdomain
    tld_in_s = 0
    subdomains = hostname.split('.')[:-2]
    for sub in subdomains:
        for tld in tlds:
             if tld in sub:
                 tld_in_s = 1
                 break
    features.append(tld_in_s)
    
    # 42. abnormal_subdomain
    features.append(1 if 'www' in hostname and not hostname.startswith('www') else 0)
    
    # 43. nb_redirection
    features.append(path.count('//'))
    
    # 44. nb_external_redirection
    features.append(path.count('http'))
    
    # 45. shortest_word_path
    features.append(min(len(w) for w in words_path) if words_path else 0)
    
    # 46. longest_word_path
    features.append(max(len(w) for w in words_path) if words_path else 0)
    
    # 47. avg_word_path
    features.append(sum(len(w) for w in words_path) / len(words_path) if words_path else 0)
    
    # 48. google_index (Dummy 0, as we can't check)
    features.append(0)
    # 49. page_rank (Dummy 0)
    features.append(0)

    # Note: Returning 49 features now including 2 dummies to match dataset potentially better or just stick to lexical?
    # Let's stick to 49 to leverage potential model patterns if re-trained later with better data
    # Actually, let's DROP the dummies if we aren't using them in training mapping.
    # I will stick to 47 meaningful ones.
    
    return np.array(features[:-2]).reshape(1, -1)
