import requests
def get_mac_vendor(mac_address):
    """Returns device vendor based on MAC address"""
    url = f"https://api.macvendors.com/{mac_address}"
    try:
        response = requests.get(url, timeout=2)
        if response.status_code == 200:
            return response.text
    except requests.RequestException:
        pass
    return "Unknown"