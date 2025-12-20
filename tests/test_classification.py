import os
import sys
from pathlib import Path

current_dir = Path(__file__).resolve().parent
parent_dir = str(current_dir.parent)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)
src_dir = f"{parent_dir}/src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))
import logging

from test_harness import get_master_classification

# Import DNS lookup function
from src.database.localhosts import get_localhosts
from src.utils.client import classify_client, export_client_definition

# Configure logging
logger = logging.getLogger(__name__)

# Folder to save client definitions
OUTPUT_FOLDER = "tests/client_definitions"


def save_client_data(ip_address, data):
    """
    Save client data to a JSON file.

    Args:
        ip_address (str): The IP address used as the filename.
        data (dict): The client data to save.
    """
    if not os.path.exists(OUTPUT_FOLDER):
        os.makedirs(OUTPUT_FOLDER)

    file_path = os.path.join(OUTPUT_FOLDER, f"{ip_address}.json")
    try:
        with open(file_path, "w") as file:
            json.dump(data, file, indent=4)
        logging.info(f"Saved client data for {ip_address} to {file_path}")
    except IOError as e:
        logging.error(f"Failed to save client data for {ip_address}: {e}")


def main():
    # Statistics tracking
    total_clients = 0
    classified_clients = 0
    master_data_matches = 0
    master_data_mismatches = 0
    classification_details = []

    # Get all localhost data
    localhosts = get_localhosts()

    print("\n===== STARTING CLASSIFICATION TEST =====")

    for eachip in localhosts:
        total_clients += 1
        client_data = export_client_definition(eachip)
        save_client_data(eachip, client_data)

        if client_data:
            print(f"Client data retrieved for {eachip}")
            result = classify_client("TESTPPE", client_data)
            print(f"Result: {result}")
            if result:
                classified_clients += 1

                # Get API classification result
                best_match = result.get("best_match", ["UNKNOWN"])
                api_category = (
                    best_match[0]
                    if best_match and isinstance(best_match, (list, tuple))
                    else "UNKNOWN"
                )

                # Get expected classification from master data
                expected_category = get_master_classification(eachip)

                if expected_category:
                    # Compare API result with expected result
                    if api_category == expected_category:
                        master_data_matches += 1
                        match_status = "MATCH ✓"
                    else:
                        master_data_mismatches += 1
                        match_status = "MISMATCH ✗"

                    print(
                        f"Client {eachip}: API: {api_category}, Expected: {expected_category} - {match_status}"
                    )

                    # Store the comparison result for summary
                    classification_details.append(
                        {
                            "ip": eachip,
                            "api": api_category,
                            "expected": expected_category,
                            "match": api_category == expected_category,
                        }
                    )
                else:
                    print(
                        f"Client {eachip}: API: {api_category}, No expected classification available"
                    )
                    classification_details.append(
                        {
                            "ip": eachip,
                            "api": api_category,
                            "expected": "N/A",
                            "match": None,
                        }
                    )
            else:
                print(f"Failed to classify client {eachip}")
        else:
            print(f"Failed to fetch client data for {eachip}")

    # Calculate statistics
    accuracy = 0
    if master_data_matches + master_data_mismatches > 0:
        accuracy = (
            master_data_matches / (master_data_matches + master_data_mismatches)
        ) * 100

    # Print comprehensive summary
    print("\n" + "=" * 50)
    print("         CLASSIFICATION TEST RESULTS         ")
    print("=" * 50)
    print(f"Total clients processed:     {total_clients}")
    print(f"Successfully classified:     {classified_clients}")
    print(
        f"Clients with master data:    {master_data_matches + master_data_mismatches}"
    )
    print(f"Correct classifications:     {master_data_matches}")
    print(f"Incorrect classifications:   {master_data_mismatches}")
    print(f"Classification accuracy:     {accuracy:.2f}%")
    print("-" * 50)

    # Print a table of results if there are any
    if classification_details:
        print("\nDETAILED CLASSIFICATION RESULTS:")
        print("-" * 75)
        print(f"{'IP ADDRESS':<20} {'API RESULT':<20} {'EXPECTED':<20} {'MATCH':<10}")
        print("-" * 75)

        for detail in classification_details:
            match_symbol = (
                "✓"
                if detail["match"] == True
                else "✗" if detail["match"] == False else "-"
            )
            print(
                f"{detail['ip']:<20} {detail['api']:<20} {detail['expected']:<20} {match_symbol:<10}"
            )

        print("-" * 75)

    print("\nClassification test completed.")


if __name__ == "__main__":
    main()
