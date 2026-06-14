import requests
import random

def enrich_ip(ip_address):
    """
    Queries a free geolocation API to enrich an IP address with Country, City, Coordinates, and ISP.
    Falls back to mock threat intelligence / reputation scoring.
    """
    # Exclude internal/private IP addresses
    if not ip_address or ip_address in ["127.0.0.1", "localhost", "::1"] or ip_address.startswith("192.168.") or ip_address.startswith("10.") or ip_address.startswith("172.16."):
        return {
            "country": "INTERNAL",
            "country_code": "US",
            "city": "Internal Network",
            "latitude": 37.7749,
            "longitude": -122.4194,
            "isp": "Local AWS VPC / Internal",
            "abuse_score": 0,
            "is_malicious": False
        }
        
    try:
        # Fetch geolocation via free ip-api.com (no key required, HTTP format)
        url = f"http://ip-api.com/json/{ip_address}"
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                # Simulated threat intelligence (Abuse score)
                # For demo purposes, we will mock a score. Let's make it look authentic:
                # IPs from certain ranges get higher scores, or random for demo.
                abuse_score = random.randint(0, 15)
                # If we want a high threat IP for testing:
                if ip_address.startswith("185.") or ip_address.startswith("45."):
                    abuse_score = random.randint(70, 99)
                    
                return {
                    "country": data.get("country", "Unknown"),
                    "country_code": data.get("countryCode", "US"),
                    "city": data.get("city", "Unknown"),
                    "latitude": data.get("lat", 0.0),
                    "longitude": data.get("lon", 0.0),
                    "isp": data.get("isp", "Unknown"),
                    "abuse_score": abuse_score,
                    "is_malicious": abuse_score > 50
                }
    except Exception as e:
        print(f"[-] Geolocation API error for {ip_address}: {e}")
        
    # Return a realistic mock if API fails
    mock_countries = [
        {"name": "Russia", "code": "RU", "lat": 55.7558, "lon": 37.6173},
        {"name": "China", "code": "CN", "lat": 39.9042, "lon": 116.4074},
        {"name": "United States", "code": "US", "lat": 37.0902, "lon": -95.7129},
        {"name": "Netherlands", "code": "NL", "lat": 52.1326, "lon": 5.2913},
        {"name": "Germany", "code": "DE", "lat": 51.1657, "lon": 10.4515}
    ]
    country = random.choice(mock_countries)
    score = random.randint(0, 95)
    
    return {
        "country": country["name"],
        "country_code": country["code"],
        "city": "Simulated Gateway",
        "latitude": country["lat"],
        "longitude": country["lon"],
        "isp": "ThreatIntel Mock ISP",
        "abuse_score": score,
        "is_malicious": score > 50
    }

if __name__ == "__main__":
    # Test with Google DNS IP
    print("Testing IP enrichment with 8.8.8.8:")
    print(enrich_ip("8.8.8.8"))
