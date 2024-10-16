from flask import Flask, request, jsonify, redirect, session
from flask_cors import CORS
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
import google.generativeai as genai
import os

# Setup Flask
app = Flask(__name__)
CORS(app)
app.secret_key = os.environ.get("SECRET_KEY")

# Gemini API configuration
genai.configure(api_key=os.environ["GEMINI_API_KEY"])

# Google OAuth configuration
GOOGLE_CLIENT_ID = os.environ["GOOGLE_CLIENT_ID"]
GOOGLE_CLIENT_SECRET = os.environ["GOOGLE_CLIENT_SECRET"]
REDIRECT_URI = "https://100.20.92.101/callback"

flow = Flow.from_client_config(
    {
        "web": {
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "redirect_uris": [REDIRECT_URI],
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
        }
    },
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "openid"],
)

@app.route("/login")
def login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)

@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials
    user_info = credentials.id_token
    return jsonify({"user": user_info})

@app.route("/chat", methods=["POST"])
def chat():
    input_text = request.json["input"]
    model = genai.GenerativeModel(model_name="gemini-1.5-pro-002")

    response = model.start_chat(
        history=[
            {
                "role": "user",
                "parts": ["Understand the PDFs and answer questions based on them."],
            }
        ]
    ).send_message(input_text)

    return jsonify({"text": response.text})

if __name__ == "__main__":
    app.run(debug=True)
