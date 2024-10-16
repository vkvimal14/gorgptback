from flask import Flask, request, jsonify, redirect, session, url_for
from flask_cors import CORS
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from functools import wraps
import google.generativeai as genai
import os
import time

# Setup Flask
app = Flask(__name__)
# Configure CORS with specific origins

# Allow requests from localhost:3000 for development
CORS(app, origins=['http://localhost:3000'], supports_credentials=True)
app.secret_key = os.environ.get("SECRET_KEY")
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour session lifetime

# Gemini API configuration
genai.configure(api_key=os.environ["GEMINI_API_KEY"])

# Google OAuth configuration
GOOGLE_CLIENT_ID = os.environ["GOOGLE_CLIENT_ID"]
GOOGLE_CLIENT_SECRET = os.environ["GOOGLE_CLIENT_SECRET"]
REDIRECT_URI = "https://gorgptback.onrender.com/callback"

# Error messages
ERROR_MESSAGES = {
    'unauthorized': 'Please log in to access this resource',
    'invalid_token': 'Invalid or expired session',
    'server_error': 'An internal server error occurred'
}

# Initialize the OAuth flow
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
    scopes=[
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email",
        "openid"
    ]
)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': ERROR_MESSAGES['unauthorized']}), 401
        return f(*args, **kwargs)
    return decorated_function

def init_gemini_model():
    """Initialize the Gemini model with configuration"""
    generation_config = {
        "temperature": 1,
        "top_p": 0.95,
        "top_k": 40,
        "max_output_tokens": 8192,
    }
    
    return genai.GenerativeModel(
        model_name="gemini-1.5-pro-002",
        generation_config=generation_config,
    )

@app.before_request
def before_request():
    """Ensure all requests use HTTPS"""
    if not request.is_secure:
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)

@app.route("/login")
def login():
    try:
        authorization_url, state = flow.authorization_url(
            prompt="consent",
            access_type="offline",
            include_granted_scopes="true"
        )
        session["state"] = state
        return jsonify({"auth_url": authorization_url})
    except Exception as e:
        app.logger.error(f"Login error: {str(e)}")
        return jsonify({"error": ERROR_MESSAGES['server_error']}), 500

@app.route("/callback")
def callback():
    try:
        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials
        
        # Store user information in session
        session['user_id'] = credentials.id_token.get('sub')
        session['email'] = credentials.id_token.get('email')
        session['user_name'] = credentials.id_token.get('name')
        session.permanent = True
        
        return jsonify({
            "success": True,
            "user": {
                "id": session['user_id'],
                "email": session['email'],
                "name": session['user_name']
            }
        })
    except Exception as e:
        app.logger.error(f"Callback error: {str(e)}")
        return jsonify({"error": ERROR_MESSAGES['server_error']}), 500

@app.route("/chat", methods=["POST"])
@login_required
def chat():
    try:
        input_text = request.json.get("input")
        if not input_text:
            return jsonify({"error": "Input text is required"}), 400

        # Get or initialize chat session
        if 'chat_session' not in session:
            model = init_gemini_model()
            session['chat_session'] = model.start_chat(
                history=[
                    {
                        "role": "user",
                        "parts": ["You are a helpful assistant. Please provide accurate and relevant information based on user queries."],
                    }
                ]
            )
        
        # Send message and get response
        response = session['chat_session'].send_message(input_text)
        
        return jsonify({
            "text": response.text,
            "user": session.get('user_name')
        })
    except Exception as e:
        app.logger.error(f"Chat error: {str(e)}")
        return jsonify({"error": ERROR_MESSAGES['server_error']}), 500

@app.route("/logout")
@login_required
def logout():
    try:
        session.clear()
        return jsonify({"success": True, "message": "Logged out successfully"})
    except Exception as e:
        app.logger.error(f"Logout error: {str(e)}")
        return jsonify({"error": ERROR_MESSAGES['server_error']}), 500

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "timestamp": time.time()
    })

if __name__ == "__main__":
    app.run(debug=False)