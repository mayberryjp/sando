import requests
import json
import sys
import time
from datetime import datetime

def recalculate_threat_scores(base_url="http://localhost:8044"):
    """
    Send a POST request to trigger threat score recalculation
    
    Args:
        base_url: Base URL of the API server (default: http://localhost:8080)
        
    Returns:
        None - prints results to console
    """
    endpoint = f"{base_url}/api/threatscore"
    
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Sending request to recalculate threat scores...")
    print(f"Endpoint: {endpoint}")
    
    try:
        # Record the start time to measure performance
        start_time = time.time()
        
        # Send POST request to the endpoint
        response = requests.post(endpoint)
        
        # Calculate elapsed time
        elapsed_time = time.time() - start_time
        
        # Check if request was successful
        if response.status_code == 200:
            # Parse the JSON response
            data = response.json()
            
            print(f"\n✅ Success! Recalculation completed in {elapsed_time:.2f} seconds")
            print(f"Message: {data.get('message', 'No message provided')}")
            
            # Display statistics
            host_count = data.get('host_count', 0)
            print(f"\nProcessed {host_count} hosts")
            
            # Display some sample scores if available
            scores = data.get('scores', {})
            if scores:
                print("\nSample threat scores (first 10):")
                for i, (ip, score) in enumerate(list(scores.items())[:10]):
                    print(f"  {ip}: {score}")
                
                if len(scores) > 10:
                    print(f"  ... and {len(scores) - 10} more")
            else:
                print("\nNo threat scores returned in the response")
                
        else:
            print(f"\n❌ Error: Received status code {response.status_code}")
            print(f"Response: {response.text}")
            
    except requests.exceptions.ConnectionError:
        print(f"\n❌ Error: Could not connect to {endpoint}")
        print("Make sure the server is running and the URL is correct")
    except requests.exceptions.Timeout:
        print(f"\n❌ Error: Request timed out")
    except requests.exceptions.RequestException as e:
        print(f"\n❌ Error: An error occurred while making the request: {e}")
    except json.JSONDecodeError:
        print(f"\n❌ Error: Could not parse response as JSON")
        print(f"Response: {response.text}")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")

if __name__ == "__main__":
    # Allow custom URL from command line argument
    base_url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8044"
    recalculate_threat_scores(base_url)