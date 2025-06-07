import requests
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

API_ENDPOINTS = [
  #  "http://localhost:8044/api/online/explore",
    "http://localhost:8044/api/online/consolidated",
 #   "http://localhost:8044/api/client/192.168.49.80",
    "http://localhost:8044/api/localhosts"
]
NUM_REQUESTS_PER_ENDPOINT = 200
MAX_WORKERS = 50

def send_request(url):
    try:
        response = requests.get(url, timeout=60)
        return (url, response.status_code, response.elapsed.total_seconds())
    except Exception as e:
        return (url, "ERROR", str(e))

def main():
    start_time = time.time()
    futures = []
    results = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        for url in API_ENDPOINTS:
            for _ in range(NUM_REQUESTS_PER_ENDPOINT):
                futures.append(executor.submit(send_request, url))

        for future in as_completed(futures):
            results.append(future.result())

    # Print summary
    for url in API_ENDPOINTS:
        url_results = [r for r in results if r[0] == url]
        success = sum(1 for r in url_results if r[1] == 200)
        errors = [r for r in url_results if r[1] != 200]
        print(f"\nResults for {url}:")
        print(f"  Success: {success}/{NUM_REQUESTS_PER_ENDPOINT}")
        if errors:
            print(f"  Errors: {len(errors)}")
            for err in errors[:5]:  # Show up to 5 errors
                print(f"    {err}")

    print(f"\nTotal time: {time.time() - start_time:.2f} seconds")

if __name__ == "__main__":
    main()