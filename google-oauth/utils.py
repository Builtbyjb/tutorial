import os
from google_auth_oauthlib.flow import Flow
import requests
from typing import Optional
from constants import TOKEN_INFO_URL, TOKEN_URL
import secrets


def verify_token(access_token: str) -> bool:
  """ Verify google access token."""
  try: response = requests.get(TOKEN_INFO_URL, params={'access_token': access_token}, timeout=10)
  except Exception as e:
    print(f"Error verifying access token: {e}")
    return False

  if response.status_code != 200:
    print("Error verifying access token")
    return False
  return


def refresh_access_token(refresh_token: str, client_id: str, client_secret: str) -> Optional[str]:
  """Refresh google access token."""
  payload = {
    'client_id': client_id,
    'client_secret': client_secret,
    'refresh_token': refresh_token,
    'grant_type': 'refresh_token'
  }

  try:
    response = requests.post(TOKEN_URL, data=payload, timeout=15)
    if response.status_code == 200:
      token_json = response.json()
      return  str(token_json["access_token"])

    print(f"Token Refresh Error: {response.status_code} : {response.text}")
    return None
  except requests.exceptions.Timeout:
    print("Token Refresh Error: Request timed out.")
    return


def auth_config() -> Flow:
  """Google user authentication oauth configuration"""
  scopes = [
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
  ]
  client_id = os.getenv("CLIENT_ID")
  client_secret = os.getenv("CLIENT_SECRET")
  server_url = os.getenv("SERVER_URL")

  if client_id is None: raise ValueError("Google client id is not found")
  if client_secret is None: raise ValueError ("Google signin client secret not found")
  if server_url is None: raise ValueError("Google server url is not set")

  redirect_url = f"{server_url}/google/callback/sign-in"

  client_config = {
    "web": {
      "client_id": client_id,
      "client_secret": client_secret,
      "auth_uri": "https://accounts.google.com/o/oauth2/auth",
      "token_uri": "https://oauth2.googleapis.com/token",
      "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
      "redirect_uris": [redirect_url],
    }
  }
  return Flow.from_client_config(client_config, scopes=scopes, redirect_uri=redirect_url)


def generate_crypto_string(length: int=32) -> str:
  required_bytes = (length * 6 + 7) // 8  # Calculate bytes needed for the desired length
  token = secrets.token_urlsafe(required_bytes)
  return token[:length]
