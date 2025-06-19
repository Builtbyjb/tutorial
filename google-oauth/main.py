from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, JSONResponse
import uvicorn
from dotenv import load_dotenv
from fastapi.templating import Jinja2Templates
from utils import auth_config, generate_crypto_string, auth_session
from datetime import datetime, timedelta, timezone
from typing import Union, Dict, Any, Optional
import os
import requests
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from constants import TOKEN_URL
from contextlib import asynccontextmanager
from database import get_session, User, create_db_and_tables, TokenUpdate, CACHE, DB

load_dotenv()

@asynccontextmanager
async def lifespan(app: FastAPI) -> Any:
  create_db_and_tables()
  yield

app = FastAPI(lifespan=lifespan)

templates = Jinja2Templates(directory="templates")


@app.get("/")
async def index(request: Request):
	return templates.TemplateResponse( request=request, name="index.html")


@app.get("/home")
async def home(request: Request, db: DB):
  session_id = request.cookies.get("session_id")
  if auth_session(session_id, db):
    return templates.TemplateResponse(
      request=request, name="home.html", context={}
    )
  else:
    return RedirectResponse("/")


@app.get("/sign-in")
async def sign_in() -> RedirectResponse:
  config = auth_config()
  url, state = config.authorization_url(access_type="offline", prompt="consent")

  response = RedirectResponse(url=url, status_code=302)
  expires = datetime.now(timezone.utc) + timedelta(minutes=5)
  response.set_cookie(
    key="state",
    value=state,
    expires=expires,
    path="/",
    secure=True,
    httponly=True,
    samesite="lax"
  )
  return response


@app.get("/sign-out")
async def sign_out() -> RedirectResponse:
  response = RedirectResponse(url="/", status_code=302)
  expires = datetime.now(timezone.utc) + timedelta(minutes=5)
  response.set_cookie(
    key="session_id",
    value="",
    expires=expires,
    path="/",
    secure=True,
    httponly=True,
    samesite="lax"
  )
  return response


@app.get("/callback/auth",  response_model=None)
async def callback(request: Request, db: DB) -> Union[JSONResponse, RedirectResponse]:
  """Completes google sign-in oauth flow"""
  # Verify state parameter
  if request.query_params.get("state") != request.cookies.get("state"):
    print("Invalid state parameter")
    return JSONResponse(content={"error": "Invalid state parameter"}, status_code=400)

  client_id = os.getenv("CLIENT_ID")
  client_secret = os.getenv("CLIENT_SECRET")
  server_url = os.getenv("SERVER_URL")

  if client_id is None: raise ValueError("Google sign client ID is not set")
  if client_secret is None: raise ValueError("Google sign client secret is not set")
  if server_url is None: raise ValueError("Server URL is not set")
  redirect_url = f"{server_url}/google/callback/sign-in"

  # Get authorization tokens
  try:
    code = request.query_params.get("code")
    if code is None:
      return JSONResponse(content={"error": "Authorization code not in request"}, status_code=400)

    payload: Dict[str, str] = {
      "code": code,
      "client_id": client_id,
      "client_secret": client_secret,
      "redirect_uri": redirect_url,
      "grant_type": "authorization_code"
    }

    res = requests.post(TOKEN_URL, data=payload)
    token = res.json()
  except Exception as e:
    print("Failed to get authorization tokens")
    return JSONResponse(content=str(e), status_code=500)

  # Get user information
  try:
    user_info: Any = id_token.verify_oauth2_token(
      token["id_token"],
      google_requests.Request(),
      client_id
    )
  except Exception as e:
    print(e)
    return JSONResponse(content=str(e), status_code=500)

  # print(user_info)

  user_id = user_info.get("sub")
  assert isinstance(user_id, str)

  username = user_info.get("name")
  assert isinstance(username, str)

  email = user_info.get("email")
  assert isinstance(email, str)

  access_token = token["access_token"]
  session_id: str = generate_crypto_string()
  refresh_token: Optional[str] = None

  try: refresh_token = token["refresh_token"]
  except KeyError: print("Refresh token not found")

  # Check if the user exists before adding to database
  user = db.get(User, user_id)
  if user is None:
    user = User(
      id=user_id,
      name=username,
      access_token=access_token,
      refresh_token=refresh_token
    )
    # Add user to database
    db.add(user)
    db.commit
    db.refresh(user)
  else:
    #  Update access token and refresh token
    new_token = TokenUpdate(
      access_token=access_token, 
      refresh_token=refresh_token
    )

    user.sqlmodel_update(new_token.model_dump(exclude_unset=True))
    db.add(user)
    db.commit()
    db.refresh(user)

  CACHE.set(session_id, user_id)

  # Set user authentication cookie
  response = RedirectResponse(url="/home", status_code=302)
  expires = datetime.now(timezone.utc) + timedelta(days=7)
  response.set_cookie(
    key="session_id",
    value=session_id,
    expires=expires,
    path="/",
    secure=True,
    httponly=True,
    samesite="lax"
  )
  return response


if __name__ == "__main__":
  uvicorn.run("main:app", host="0.0.0.0", port=3000, reload=True)
