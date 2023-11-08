import requests


url = 'http://localhost:8080' 

try:
    # Send an HTTP GET request to the server
    response = requests.get(url)

    # Check if the request was successful (HTTP status code 200)
    if response.status_code == 200:
        print('HTTP request successful')
        print('Server Response:')
        print(response.text)  # This will print the response content from the server
    else:
        print(f'Failed to send HTTP request. Status code: {response.status_code}')
except requests.exceptions.RequestException as e:
    print(f'Error: {e}')
