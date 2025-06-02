import requests

BASE_URL = "http://localhost:8044"

def test_api_explore():
    url = f"{BASE_URL}/api/explore"
    params = {"limit": 1, "page": 0}
    resp = requests.get(url, params=params)
    print("GET /api/explore:", resp.status_code)
    print(resp.json())

def test_api_explore_search():
    url = f"{BASE_URL}/api/explore/search"
    params = {"q": "192.168", "page": 0, "page_size": 1}
    resp = requests.get(url, params=params)
    print("GET /api/explore/search:", resp.status_code)
    print(resp.json())

if __name__ == "__main__":
    test_api_explore()
    test_api_explore_search()