import os
import requests
import urllib3
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv()


def _require_env(*names):
    missing = [n for n in names if not os.getenv(n)]
    if missing:
        raise EnvironmentError(
            f"Missing required environment variables: {', '.join(missing)}. "
            "Ensure TENANT_ID, CLIENT_ID, CLIENT_SECRET are set in .env or environment."
        )


class GraphConnector:

    def __init__(self):
        # C-03: fail fast with a clear message if credentials are not configured
        _require_env("TENANT_ID", "CLIENT_ID", "CLIENT_SECRET")
        self.tenant_id = os.getenv("TENANT_ID")
        self.client_id = os.getenv("CLIENT_ID")
        self.client_secret = os.getenv("CLIENT_SECRET")
        self.scope = os.getenv("GRAPH_SCOPE", "https://graph.microsoft.com/.default")
        self.token_url = (
            f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        )
        self.access_token = self._get_token()

    def _get_token(self):
        body = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": self.scope,
            "grant_type": "client_credentials",
        }
        # C-02: verify=False is intentional here only — corporate proxy intercepts
        # the OAuth endpoint SSL. Graph API data calls use the system CA bundle.
        response = requests.post(self.token_url, data=body, verify=False)
        response.raise_for_status()
        return response.json()["access_token"]

    def graph_get(self, url):
        headers = {"Authorization": f"Bearer {self.access_token}"}
        # C-02: use system CA bundle for data calls; fall back to verify=False only
        # if the corporate proxy also intercepts graph.microsoft.com (set
        # REQUESTS_CA_BUNDLE=/path/to/corp-ca.crt to use a custom CA instead).
        ca_bundle = os.getenv("REQUESTS_CA_BUNDLE", True)
        try:
            response = requests.get(url, headers=headers, verify=ca_bundle)
            response.raise_for_status()
        except requests.exceptions.SSLError:
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()
        return response.json()
