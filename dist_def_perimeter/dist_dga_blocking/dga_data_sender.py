import requests
import sys

def db_post(domain):
    # URL of the endpoint you want to send the POST request to
    url = "http://localhost:5000/dga"

    # JSON data to be sent in the request body
    payload = {
        "qname": domain
    }

    # Send the POST request
    response = requests.post(url, json=payload)

    # Check the response status code
    if response.status_code == 200:
        print("POST request was successful.")
    else:
        print(f"POST request failed with status code: {response.status_code}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Need to give domain to add to db")
    else:
        db_post(sys.argv[1])