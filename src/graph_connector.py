import os
import requests
import urllib3
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv()

TENANT_ID = os.getenv("TENANT_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
GRAPH_SCOPE = os.getenv(
    "GRAPH_SCOPE",
    "https://graph.microsoft.com/.default"
)

TOKEN_URL = (
    f"https://login.microsoftonline.com/"
    f"{TENANT_ID}/oauth2/v2.0/token"
)

class GraphConnector:

    def __init__(self):
        self.access_token = self.get_token()

    def get_token(self):

        body = {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "scope": GRAPH_SCOPE,
            "grant_type": "client_credentials"
        }

        response = requests.post(TOKEN_URL, data=body, verify=False)

        response.raise_for_status()

        return response.json()["access_token"]

    def graph_get(self, url):

        headers = {
            "Authorization": f"Bearer {self.access_token}"
        }

        response = requests.get(url, headers=headers, verify=False)

        response.raise_for_status()

        return response.json()
