import json
import urllib.request


def call(method, url, headers, body=None, timeout=30):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json", "Accept": "application/json", **headers})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # HTTPError/URLError are OSError
        raw = r.read()
    return json.loads(raw) if raw else None
