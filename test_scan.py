import urllib.request
import urllib.parse
import json

url = "http://localhost:8000"

def do_req(endpoint, data=None, method="POST", headers=None):
    if headers is None:
        headers = {}
    
    if data is not None:
        if isinstance(data, dict) and "username" in data:
            # form urlencoded
            payload = urllib.parse.urlencode(data).encode('utf-8')
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            payload = json.dumps(data).encode('utf-8')
            headers["Content-Type"] = "application/json"
    else:
        payload = None

    req = urllib.request.Request(url + endpoint, data=payload, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as response:
            return response.status, json.loads(response.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()

def test_scan():
    print("Logging in...")
    status, res = do_req("/api/auth/token", {"username": "ujjawal@123.com", "password": "password123"})
    if status != 200:
        print(f"Login failed: {status} {res}")
        return
    token = res["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    print("Creating project...")
    status, res = do_req("/api/projects", {"name": "Test Scan Project"}, headers=headers)
    if status != 201:
        print(f"Project creation failed: {status} {res}")
        return
    project_id = res["id"]

    print("Creating api request...")
    req_payload = {
        "project_id": project_id,
        "name": "Test Request",
        "raw_request": "GET /api/users/2/profile HTTP/1.1\r\nHost: localhost:8001\r\nAuthorization: Bearer YOUR_TOKEN_HERE\r\nAccept: application/json\r\n\r\n",
        "user_tokens": [{"label": "Admin", "token": "mock-admin-token"}]
    }
    status, res = do_req("/api/requests", req_payload, headers=headers)
    if status != 201:
        print(f"Request creation failed: {status} {res}")
        return
    api_request_id = res["id"]

    print("Starting scan...")
    scan_payload = {
        "api_request_id": api_request_id,
        "enabled_modules": ["idor"]
    }
    status, res = do_req("/api/scans/start", scan_payload, headers=headers)
    if status not in (200, 201, 202):
        print(f"Scan start failed: {status} {res}")
        return
    
    print(f"Scan started successfully: {res}")

test_scan()
