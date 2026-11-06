import urllib.request
import urllib.parse
from config import Config
from scanner.validator import URLValidator

class SafeHTTPClient:
    @staticmethod
    def request(url: str, method: str = "GET", data: bytes = None, headers: dict = None) -> tuple[int, dict, str]:
        current_url = url
        redirects = 0

        while redirects <= Config.MAX_REDIRECTS:
            is_valid, msg = URLValidator.validate_url(current_url)
            if not is_valid:
                raise ValueError(f"Redirect target blocked by security validator: {msg}")

            req_headers = headers or {}
            if 'User-Agent' not in req_headers:
                req_headers['User-Agent'] = 'WebSecurityScanner/1.0 (Non-destructive security assessment)'

            req = urllib.request.Request(current_url, data=data, headers=req_headers, method=method)

            class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    return None

            opener = urllib.request.build_opener(NoRedirectHandler)

            try:
                with opener.open(req, timeout=Config.HTTP_TIMEOUT) as resp:
                    status = resp.status
                    resp_headers = dict(resp.info())
                    content_bytes = resp.read(Config.MAX_RESPONSE_SIZE + 1)
                    if len(content_bytes) > Config.MAX_RESPONSE_SIZE:
                        content_bytes = content_bytes[:Config.MAX_RESPONSE_SIZE]
                    body = content_bytes.decode('utf-8', errors='replace')
                    return status, resp_headers, body
            except urllib.error.HTTPError as e:
                if e.code in (301, 302, 303, 307, 308):
                    location = e.headers.get('Location')
                    if not location:
                        raise ValueError("Redirect response missing Location header.")
                    current_url = urllib.parse.urljoin(current_url, location)
                    redirects += 1
                    continue
                else:
                    body = e.read(Config.MAX_RESPONSE_SIZE).decode('utf-8', errors='replace')
                    return e.code, dict(e.headers), body
            except Exception as e:
                raise RuntimeError(f"HTTP Request failed: {str(e)}")

        raise RuntimeError(f"Exceeded maximum redirect limit of {Config.MAX_REDIRECTS}.")
