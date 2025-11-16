# PediaPilot
This is an app which enlightens every single student.
import streamlit as st
import requests
import json
import time
from urllib.parse import urlencode
from google_auth_oauthlib.flow import Flow
import jwt  # PyJWT
from datetime import datetime, timedelta

# -----------------------------------------------------------------------------
# Configuration — insert these into Streamlit secrets (see instructions below)
# -----------------------------------------------------------------------------
# Required st.secrets keys:
# {
#   "APP_BASE_URL": "http://localhost:8501",
#   "GOOGLE_CLIENT_ID": "...",
#   "GOOGLE_CLIENT_SECRET": "...",
#   "APPLE_CLIENT_ID": "...",        # Service ID (e.g. com.example.web)
#   "APPLE_TEAM_ID": "...",
#   "APPLE_KEY_ID": "...",
#   "APPLE_PRIVATE_KEY": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
#   "APPLE_REDIRECT_URI": "http://localhost:8501",
#   "OAUTH_SCOPES": "openid email profile"
# }
# -----------------------------------------------------------------------------

# Helper: safe read secret
def secret(key, default=None):
    return st.secrets.get(key, default)

APP_BASE = secret("APP_BASE_URL", "http://localhost:8501")
GOOGLE_CLIENT_ID = secret("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = secret("GOOGLE_CLIENT_SECRET")
APPLE_CLIENT_ID = secret("APPLE_CLIENT_ID")
APPLE_TEAM_ID = secret("APPLE_TEAM_ID")
APPLE_KEY_ID = secret("APPLE_KEY_ID")
APPLE_PRIVATE_KEY = secret("APPLE_PRIVATE_KEY")
APPLE_REDIRECT_URI = secret("APPLE_REDIRECT_URI", APP_BASE)
OAUTH_SCOPES = secret("OAUTH_SCOPES", "openid email profile")

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.user = None
    st.session_state.provider = None
    st.session_state._oauth_state = None  # keeps state for CSRF checks

st.set_page_config(page_title="StudyBuddy AI — Secure Access", layout="wide")

# Remove legacy username/password UI: only social sign-in buttons displayed
def build_header():
    st.markdown("<h1 style='color:#2E4053;'>StudyBuddy AI — Secure Access</h1>", unsafe_allow_html=True)
    st.write("Access your study dashboard using your Google or Apple account. This application uses OAuth 2.0 for authentication. Your email and basic profile data are used only for identification within the application.")

build_header()
st.markdown("---")

# Logout function
def do_logout():
    st.session_state.logged_in = False
    st.session_state.user = None
    st.session_state.provider = None
    st.session_state._oauth_state = None
    # clear query params so callback won't be processed repeatedly
    st.experimental_set_query_params()
    st.success("You have been signed out.")

# If user is logged in, show dashboard
if st.session_state.logged_in:
    st.sidebar.success(f"Signed in as: {st.session_state.user.get('email') or 'Unknown'}")
    if st.sidebar.button("Sign out"):
        do_logout()

    # Minimal dashboard content (can be expanded)
    st.subheader("Dashboard")
    st.write(f"Welcome, {st.session_state.user.get('name') or st.session_state.user.get('email')}!")
    st.write("Use the navigation sidebar to access the learning tools. Authentication is provided exclusively via Google and Apple for improved security.")
    st.stop()

# Not logged in: show only social sign-in buttons
st.write("Please sign in using one of the following providers.")

col1, col2 = st.columns(2)
with col1:
    if st.button("Sign in with Google"):
        # Start Google OAuth flow by creating an authorization URL and redirecting the browser.
        flow = Flow.from_client_config(
            client_config={
                "web": {
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "auth_uri": "https://accounts.google.com/o/oauth2/v2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token"
                }
            },
            scopes=OAUTH_SCOPES.split(),
            redirect_uri=APP_BASE  # Google will redirect back to this URL with ?state & ?code
        )

        auth_url, state = flow.authorization_url(
            access_type="offline",
            include_granted_scopes="true",
            prompt="select_account"
        )
        # Save the Flow state for verification later
        st.session_state._oauth_state = {"provider": "google", "state": state, "flow": flow}
        # Redirect user by setting a link; new tab is opened by the browser
        st.experimental_set_query_params(auth="google_start", _=int(time.time()))
        st.markdown(f"[Proceed to Google sign-in]({auth_url})")

with col2:
    if st.button("Sign in with Apple"):
        # Build Sign in with Apple authorization URL (PKCE is optional; here we use a simple state flow)
        state = str(int(time.time()))
        st.session_state._oauth_state = {"provider": "apple", "state": state}

        # Apple OIDC Authorization endpoint
        auth_params = {
            "response_type": "code",
            "response_mode": "form_post",
            "client_id": APPLE_CLIENT_ID,
            "redirect_uri": APPLE_REDIRECT_URI,
            "scope": "name email",
            "state": state
        }
        auth_url = "https://appleid.apple.com/auth/authorize?" + urlencode(auth_params)
        st.experimental_set_query_params(auth="apple_start", _=int(time.time()))
        st.markdown(f"[Proceed to Apple sign-in]({auth_url})")

st.write("---")
st.info("Note: after signing in, the provider will redirect you back to this application. If your browser blocks automatic redirects, use the link above and allow pop-ups.")

# -----------------------------------------------------------------------------
# Callback handling: detect provider responses via query parameters
# -----------------------------------------------------------------------------
qp = st.experimental_get_query_params()

# Google callback: provider will return "state" and "code" as query params
if "state" in qp and "code" in qp and st.session_state._oauth_state:
    callback_state = qp.get("state")[0]
    callback_code = qp.get("code")[0]
    saved = st.session_state._oauth_state
    if saved.get("provider") == "google" and saved.get("state") == callback_state:
        # Use the saved Flow object to fetch the token
        flow: Flow = saved.get("flow")
        try:
            flow.fetch_token(code=callback_code)
            credentials = flow.credentials
            # Get userinfo
            resp = requests.get("https://www.googleapis.com/oauth2/v3/userinfo", headers={
                "Authorization": f"Bearer {credentials.token}"
            })
            userinfo = resp.json()
            st.session_state.logged_in = True
            st.session_state.provider = "google"
            st.session_state.user = {
                "email": userinfo.get("email"),
                "name": userinfo.get("name"),
                "picture": userinfo.get("picture")
            }
            # clear query params
            st.experimental_set_query_params()
            st.experimental_rerun()
        except Exception as e:
            st.error("Google sign-in failed: " + str(e))
            st.experimental_set_query_params()

# Apple callback: Apple often posts the form; but if provider redirected back with code in query string:
if "code" in qp and st.session_state._oauth_state and st.session_state._oauth_state.get("provider") == "apple":
    # Note: Some Apple flows return form POST; Streamlit currently reads query params only.
    code = qp.get("code")[0]
    state = qp.get("state", [""])[0]
    if state != st.session_state._oauth_state.get("state"):
        st.error("Apple sign-in state mismatch.")
        st.experimental_set_query_params()
    else:
        try:
            # Build client_secret (JWT) for Apple token request
            now = int(time.time())
            claims = {
                "iss": APPLE_TEAM_ID,
                "iat": now,
                "exp": now + 15777000,  # token valid for ~6 months (adjust as needed)
                "aud": "https://appleid.apple.com",
                "sub": APPLE_CLIENT_ID
            }
            client_secret = jwt.encode(
                claims,
                APPLE_PRIVATE_KEY,
                algorithm="ES256",
                headers={"kid": APPLE_KEY_ID}
            )

            token_url = "https://appleid.apple.com/auth/token"
            token_data = {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": APPLE_REDIRECT_URI,
                "client_id": APPLE_CLIENT_ID,
                "client_secret": client_secret
            }
            token_resp = requests.post(token_url, data=token_data, headers={"Content-Type": "application/x-www-form-urlencoded"})
            token_resp.raise_for_status()
            token_json = token_resp.json()

            # Apple returns an ID token (JWT) containing user info (email). We can decode it without verification to get email/name
            id_token = token_json.get("id_token")
            id_payload = jwt.decode(id_token, options={"verify_signature": False})
            user_email = id_payload.get("email")
            user_name = id_payload.get("name") or user_email

            st.session_state.logged_in = True
            st.session_state.provider = "apple"
            st.session_state.user = {"email": user_email, "name": user_name}
            st.experimental_set_query_params()
            st.experimental_rerun()
        except Exception as e:
            st.error("Apple sign-in failed: " + str(e))
            st.experimental_set_query_params()

# If code reaches here, no callback processed and user is not logged in
st.write("If you have completed the sign-in flow and remain on this page, please check your browser's pop-up or redirect settings and then reattempt sign-in.")
