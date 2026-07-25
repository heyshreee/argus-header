import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from .utils import normalize_url

def fetch_headers(url: str, method="GET", follow_redirects=True, timeout=10):
    """
    Fetches headers from the target URL.
    Returns a dictionary containing headers, status code, and URL.
    """
    target_url = normalize_url(url)
    
    # Configure retry logic (3 attempts)
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session = requests.Session()
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    try:
        response = session.request(
            method=method,
            url=target_url,
            allow_redirects=follow_redirects,
            timeout=timeout,
            headers={"User-Agent": "HeaderScan-Tool/1.0"} # Polite User-Agent
        )
        
        return {
            "success": True,
            "url": response.url,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "http_version": response.raw.version
        }

    except requests.exceptions.Timeout:
        return {
            "success": False,
            "url": target_url,
            "error": "Request timed out. The server took too long to respond."
        }
    except requests.exceptions.SSLError:
        return {
            "success": False,
            "url": target_url,
            "error": "SSL verification failed. The certificate might be invalid."
        }
    except requests.exceptions.ConnectionError:
        return {
            "success": False,
            "url": target_url,
            "error": "Failed to connect to the server. Please check the URL and your internet connection."
        }
    except requests.exceptions.TooManyRedirects:
        return {
            "success": False,
            "url": target_url,
            "error": "Too many redirects. The URL might be in a redirect loop."
        }
    except requests.exceptions.MissingSchema:
        return {
            "success": False,
            "url": target_url,
            "error": "Invalid URL format. Missing schema (http:// or https://)."
        }
    except requests.exceptions.InvalidURL:
        return {
            "success": False,
            "url": target_url,
            "error": "Invalid URL. Please check the URL and try again."
        }
    except requests.exceptions.RequestException as e:
        return {
            "success": False,
            "url": target_url,
            "error": f"An error occurred: {str(e)}"
        }
        
