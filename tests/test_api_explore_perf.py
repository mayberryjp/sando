import time

import requests


def test_explore_endpoint():
    hosts = [
        "10.1.10.2",
        "10.2.10.2",
        "10.3.10.2",
    ]

    for host in hosts:
        url = f"http://{host}:8044/api/explore"
        results = []
        print(f"\n{'='*50}")
        print(f"Testing {url}")
        print(f"{'='*50}")

        for i in range(5):
            try:
                start = time.perf_counter()
                response = requests.get(url, timeout=5)
                elapsed = time.perf_counter() - start

                size = len(response.content)
                results.append((elapsed, size))
                print(
                    f"Request {i + 1:2d}: {elapsed:.3f}s | {size:,} bytes | HTTP {response.status_code}"
                )
            except requests.exceptions.Timeout:
                print(f"Request {i + 1:2d}: TIMEOUT (>5s)")
            except requests.exceptions.ConnectionError:
                print(f"Request {i + 1:2d}: CONNECTION REFUSED / UNREACHABLE")
            except requests.exceptions.RequestException as e:
                print(f"Request {i + 1:2d}: ERROR - {e}")

        if results:
            times = [r[0] for r in results]
            sizes = [r[1] for r in results]
            print(f"\n{len(results)}/5 requests succeeded")
            print(f"Avg time: {sum(times)/len(times):.3f}s")
            print(f"Min time: {min(times):.3f}s | Max time: {max(times):.3f}s")
            print(f"Avg size: {sum(sizes)//len(sizes):,} bytes")
        else:
            print(f"\nAll 5 requests failed")


if __name__ == "__main__":
    test_explore_endpoint()
