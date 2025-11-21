import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import requests
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, JSONResponse
from pydantic import BaseModel
import jwt

from database import db, create_document, get_documents

# Environment
from dotenv import load_dotenv
load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET", secrets.token_urlsafe(32))
JWT_ALG = "HS256"
SESSION_COOKIE = "session"
STATE_COOKIE = "oauth_state"
COOKIE_MAX_AGE = 60 * 60 * 24 * 7  # 7 days

GOOGLE_CLIENT_ID = os.getenv("OAUTH_GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("OAUTH_GOOGLE_CLIENT_SECRET")
GITHUB_CLIENT_ID = os.getenv("OAUTH_GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("OAUTH_GITHUB_CLIENT_SECRET")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def sign_session(payload: dict, expires_in: int = COOKIE_MAX_AGE) -> str:
    to_encode = payload.copy()
    to_encode["exp"] = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALG)


def verify_session(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except Exception:
        return None


class MagicLinkRequest(BaseModel):
    email: str
    name: Optional[str] = None


@app.get("/")
def read_root():
    return {"message": "Arcyn Find API is running"}


@app.get("/api/hello")
def hello():
    return {"message": "Hello from the backend API!"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
            response["database_name"] = getattr(db, "name", None) or "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response


# ---- Session Endpoints ----
@app.get("/auth/session")
def get_session(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return JSONResponse({"authenticated": False}, status_code=200)
    payload = verify_session(token)
    if not payload:
        return JSONResponse({"authenticated": False}, status_code=200)
    return {"authenticated": True, "user": {k: payload.get(k) for k in ["id", "email", "name", "provider", "picture"]}}


@app.post("/auth/logout")
def logout(response: Response):
    response = JSONResponse({"ok": True})
    response.delete_cookie(SESSION_COOKIE)
    return response


# ---- Helpers ----

def upsert_user(email: str, name: Optional[str] = None, picture: Optional[str] = None, provider: Optional[str] = None) -> str:
    existing = db["user"].find_one({"email": email}) if db else None
    if existing:
        db["user"].update_one({"_id": existing["_id"]}, {"$set": {
            "name": name or existing.get("name"),
            "picture": picture or existing.get("picture"),
            "provider": provider or existing.get("provider"),
            "updated_at": datetime.now(timezone.utc)
        }})
        return str(existing["_id"])
    # Create
    data = {
        "name": name or email.split("@")[0],
        "email": email,
        "picture": picture,
        "provider": provider or "magic",
    }
    return create_document("user", data)


# ---- OAuth: Google ----
@app.get("/auth/google")
def auth_google(request: Request):
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        raise HTTPException(status_code=400, detail="Google OAuth not configured")
    state = secrets.token_urlsafe(24)
    # store state in cookie
    resp = RedirectResponse(url="/")
    resp.set_cookie(STATE_COOKIE, state, httponly=True, secure=True, samesite="lax", max_age=600)

    redirect_uri = request.url_for("auth_google_callback")
    auth_url = (
        "https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={GOOGLE_CLIENT_ID}"
        f"&redirect_uri={redirect_uri}"
        "&response_type=code"
        "&scope=openid%20email%20profile"
        f"&state={state}"
        "&prompt=select_account"
    )
    resp.headers["Location"] = auth_url
    return resp


@app.get("/auth/google/callback")
def auth_google_callback(request: Request):
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        raise HTTPException(status_code=400, detail="Google OAuth not configured")
    params = dict(request.query_params)
    code = params.get("code")
    state = params.get("state")
    state_cookie = request.cookies.get(STATE_COOKIE)
    if not code or not state or state != state_cookie:
        raise HTTPException(status_code=400, detail="Invalid OAuth state")

    token_url = "https://oauth2.googleapis.com/token"
    redirect_uri = request.url_for("auth_google_callback")
    data = {
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": str(redirect_uri),
    }
    token_res = requests.post(token_url, data=data)
    if token_res.status_code != 200:
        raise HTTPException(status_code=400, detail="Token exchange failed")
    tokens = token_res.json()

    userinfo_res = requests.get(
        "https://www.googleapis.com/oauth2/v3/userinfo",
        headers={"Authorization": f"Bearer {tokens.get('access_token')}"}
    )
    info = userinfo_res.json()
    email = info.get("email")
    name = info.get("name")
    picture = info.get("picture")
    user_id = upsert_user(email=email, name=name, picture=picture, provider="google")

    session = sign_session({"id": user_id, "email": email, "name": name, "picture": picture, "provider": "google"})

    frontend_url = os.getenv("FRONTEND_URL") or "http://localhost:3000/"
    resp = RedirectResponse(url=frontend_url)
    resp.set_cookie(SESSION_COOKIE, session, httponly=True, secure=True, samesite="lax", max_age=COOKIE_MAX_AGE)
    resp.delete_cookie(STATE_COOKIE)
    return resp


# ---- OAuth: GitHub ----
@app.get("/auth/github")
def auth_github(request: Request):
    if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
        raise HTTPException(status_code=400, detail="GitHub OAuth not configured")
    state = secrets.token_urlsafe(24)
    resp = RedirectResponse(url="/")
    resp.set_cookie(STATE_COOKIE, state, httponly=True, secure=True, samesite="lax", max_age=600)
    redirect_uri = request.url_for("auth_github_callback")
    auth_url = (
        "https://github.com/login/oauth/authorize"
        f"?client_id={GITHUB_CLIENT_ID}"
        f"&redirect_uri={redirect_uri}"
        f"&state={state}"
        "&scope=read:user%20user:email"
    )
    resp.headers["Location"] = auth_url
    return resp


@app.get("/auth/github/callback")
def auth_github_callback(request: Request):
    if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
        raise HTTPException(status_code=400, detail="GitHub OAuth not configured")
    params = dict(request.query_params)
    code = params.get("code")
    state = params.get("state")
    state_cookie = request.cookies.get(STATE_COOKIE)
    if not code or not state or state != state_cookie:
        raise HTTPException(status_code=400, detail="Invalid OAuth state")

    token_res = requests.post(
        "https://github.com/login/oauth/access_token",
        data={
            "client_id": GITHUB_CLIENT_ID,
            "client_secret": GITHUB_CLIENT_SECRET,
            "code": code,
            "redirect_uri": str(request.url_for("auth_github_callback")),
            "state": state,
        },
        headers={"Accept": "application/json"},
    )
    if token_res.status_code != 200:
        raise HTTPException(status_code=400, detail="Token exchange failed")
    token_json = token_res.json()
    access_token = token_json.get("access_token")

    user_res = requests.get("https://api.github.com/user", headers={"Authorization": f"Bearer {access_token}"})
    user = user_res.json()

    # get primary email
    email = None
    emails_res = requests.get("https://api.github.com/user/emails", headers={"Authorization": f"Bearer {access_token}"})
    if emails_res.status_code == 200:
        emails = emails_res.json()
        primary = next((e for e in emails if e.get("primary")), None)
        email = (primary or (emails[0] if emails else {})).get("email")

    name = user.get("name") or user.get("login")
    picture = user.get("avatar_url")

    if not email:
        raise HTTPException(status_code=400, detail="GitHub email not available")

    user_id = upsert_user(email=email, name=name, picture=picture, provider="github")

    session = sign_session({"id": user_id, "email": email, "name": name, "picture": picture, "provider": "github"})

    frontend_url = os.getenv("FRONTEND_URL") or "http://localhost:3000/"
    resp = RedirectResponse(url=frontend_url)
    resp.set_cookie(SESSION_COOKIE, session, httponly=True, secure=True, samesite="lax", max_age=COOKIE_MAX_AGE)
    resp.delete_cookie(STATE_COOKIE)
    return resp


# ---- Magic Link ----
@app.post("/auth/magic-link")
def magic_link(req: MagicLinkRequest):
    if not req.email:
        raise HTTPException(status_code=400, detail="Email required")
    # Create a short-lived token
    token = sign_session({"email": req.email, "name": req.name or req.email.split("@")[0], "provider": "magic"}, expires_in=15 * 60)
    # In production, send email containing verify URL
    verify_url = f"{os.getenv('FRONTEND_URL') or 'http://localhost:3000'}/api/auth/verify?token={token}"
    # For our environment, expose backend verification endpoint too
    backend_verify = f"/auth/magic/verify?token={token}"
    return {"ok": True, "verify_url": verify_url, "backend_verify": backend_verify}


@app.get("/auth/magic/verify")
def magic_verify(token: str):
    payload = verify_session(token)
    if not payload:
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    email = payload.get("email")
    name = payload.get("name")
    user_id = upsert_user(email=email, name=name, provider="magic")
    session = sign_session({"id": user_id, "email": email, "name": name, "provider": "magic"})

    frontend_url = os.getenv("FRONTEND_URL") or "http://localhost:3000/"
    resp = RedirectResponse(url=frontend_url)
    resp.set_cookie(SESSION_COOKIE, session, httponly=True, secure=True, samesite="lax", max_age=COOKIE_MAX_AGE)
    return resp


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
