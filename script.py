import requests

# URL to which you want to send the request
url = 'http://10.190.133.22:9002/list'

# Define the headers
headers = {
    "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/118.0",
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.5",
    "Sec-GPC": "1",
    "content-type": "application/json",
    "Pragma": "no-cache",
    "Cache-Control": "no-cache"
}

# Iterate over the full range
for i in range(256):
    ip = f'192.168.111.{i}'
    payload = {
        'server': ip,
        'email': ''
    }

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=5)  # Added headers here
        print(f'Response for IP {ip}: {response.status_code}')
        if response.status_code == 200:  # or you could add: or response.status_code == SOME_OTHER_CODE:
            print(response.text)  # Print the response body
    except requests.ConnectionError:
        print(f"Failed to connect to {ip}")
    except requests.Timeout:
        print(f"Timeout for {ip}")
    except Exception as e:
        print(f"An error occurred for {ip}: {str(e)}")
