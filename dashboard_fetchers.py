import requests
import feedparser
import config

def get_threat_news():
    """Fetches the latest cybersecurity news from trusted RSS feeds."""
    feeds = [
        "https://feeds.feedburner.com/TheHackersNews",
        "https://www.bleepingcomputer.com/feed/",
        "https://krebsonsecurity.com/feed/"
    ]
    all_articles = []
    for url in feeds:
        try:
            feed = feedparser.parse(url)
            # Limit to 5 articles per feed to keep it clean
            for entry in feed.entries[:5]:
                all_articles.append({
                    'title': entry.title,
                    'link': entry.link,
                    'source': feed.feed.title
                })
        except Exception as e:
            print(f"Error fetching RSS feed {url}: {e}")
    # Sort by a property if available, otherwise just return as is
    return all_articles[:15] # Return a max of 15 articles

def get_top_attackers():
    """Fetches the top 10 most reported malicious IPs from AbuseIPDB."""
    api_key = config.ABUSEIPDB_API_KEY
    if not api_key or "PASTE" in api_key:
        return [{'error': "AbuseIPDB API key not set."}]
    
    url = "https://api.abuseipdb.com/api/v2/blacklist"
    headers = {'Key': api_key, 'Accept': 'application/json'}
    params = {'limit': 10} # Get the top 10
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=15)
        response.raise_for_status()
        data = response.json().get('data', [])
        return [{'ip': item['ipAddress'], 'country': item['countryCode']} for item in data]
    except requests.exceptions.RequestException as e:
        print(f"Error fetching top attackers from AbuseIPDB: {e}")
        return [{'error': "Could not fetch data from AbuseIPDB."}]
    