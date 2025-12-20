import sys
from pprint import pprint

import requests


def test_cors_headers(url, method="GET"):
    """
    Test CORS headers by making requests to the specified URL

    Args:
        url (str): The URL to test
        method (str): HTTP method to use (GET, POST, OPTIONS)
    """
    print(f"\n===== Testing CORS Headers with {method} request =====")

    # Headers for simulating a cross-origin request
    headers = {
        "Origin": "http://localhost:3030",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "Content-Type, Authorization",
    }

    try:
        if method == "OPTIONS":
            # For OPTIONS preflight request
            response = requests.options(url, headers=headers, timeout=10)
        elif method == "POST":
            # For POST request
            response = requests.post(url, json={}, headers=headers, timeout=10)
        else:
            # Default to GET
            response = requests.get(url, headers=headers, timeout=10)

        print(f"Status Code: {response.status_code}")

        # Extract CORS-related headers
        cors_headers = {
            k: v
            for k, v in response.headers.items()
            if k.lower().startswith("access-control")
        }

        if cors_headers:
            print("\nCORS Headers Found:")
            for header, value in cors_headers.items():
                print(f"{header}: {value}")
        else:
            print("\nNo CORS headers found in the response!")

        # Print all headers for debugging
        print("\nAll Response Headers:")
        pprint(dict(response.headers))

    except requests.exceptions.RequestException as e:
        print(f"Error making request: {e}")


if __name__ == "__main__":
    # The URL to test - replace with your actual API endpoint
    api_url = "http://localhost:8044/api/configurations"

    if len(sys.argv) > 1:
        api_url = sys.argv[1]

    # Test with different HTTP methods
    test_cors_headers(api_url, "GET")
    test_cors_headers(api_url, "OPTIONS")

    print("\nCORS header testing complete!")
