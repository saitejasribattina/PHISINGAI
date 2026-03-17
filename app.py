import os
from datetime import datetime
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
from pymongo.server_api import ServerApi
from dotenv import load_dotenv
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import re
import google.generativeai as genai
import json
import random
import string
from flask_mail import Mail, Message

TRUSTED_DATA = {
    "trusted_emails": [
        "support@paypal.com",
        "no-reply@amazon.com",
        "accounts.google.com",
        "support@microsoft.com",
        "help@bankofamerica.com",
        "support@apple.com",
        "no-reply@facebook.com",
        "security@twitter.com",
        "support@linkedin.com",
        "noreply@github.com",
        "support@netflix.com",
        "help@adobe.com",
        "support@dropbox.com",
        "support@zoom.us",
        "support@slack.com",
        "noreply@instagram.com",
        "support@whatsapp.com",
        "support@telegram.org",
        "support@airbnb.com",
        "support@uber.com",
        "support@ola.com",
        "support@flipkart.com",
        "support@paytm.com",
        "support@phonepe.com",
        "support@yahoo.com",
        "support@outlook.com",
        "support@protonmail.com",
        "support@zoho.com",
        "support@tcs.com",
        "support@infosys.com"
    ],

    "trusted_domains": [
        "https://www.paypal.com",
        "https://www.amazon.com",
        "https://www.amazon.in",
        "https://accounts.google.com",
        "https://login.microsoftonline.com",
        "https://www.apple.com",
        "https://www.facebook.com",
        "https://www.twitter.com",
        "https://www.linkedin.com",
        "https://github.com",
        "https://www.netflix.com",
        "https://www.adobe.com",
        "https://www.dropbox.com",
        "https://zoom.us",
        "https://slack.com",
        "https://www.instagram.com",
        "https://www.whatsapp.com",
        "https://telegram.org",
        "https://www.airbnb.com",
        "https://www.uber.com",
        "https://www.olacabs.com",
        "https://www.flipkart.com",
        "https://www.paytm.com",
        "https://www.phonepe.com",
        "https://mail.yahoo.com",
        "https://outlook.live.com",
        "https://proton.me",
        "https://www.zoho.com"
    ],

    "safe_words": [
        "we will never ask for your password",
        "we will never ask for otp",
        "login through official website",
        "use our mobile app",
        "contact customer support",
        "visit nearest branch",
        "privacy policy",
        "terms and conditions",
        "secure login",
        "official communication",
        "customer support team",
        "help center",
        "unsubscribe here",
        "manage your preferences",
        "your account summary",
        "monthly statement",
        "transaction details",
        "invoice attached",
        "order confirmation",
        "delivery update",
        "thank you for your purchase",
        "no action required",
        "for your information",
        "scheduled maintenance",
        "service update",
        "account notification",
        "welcome to our service",
        "verification not required",
        "safe and secure",
        "trusted platform",
        "customer care",
        "support team",
        "official email",
        "verified account",
        "secure platform",
        "data protection",
        "your privacy matters",
        "compliance update",
        "account overview",
        "billing summary",
        "noreply",
        "nptel",
    ]
}

# --- Risk Keywords (Internal Use) ---
INTERNAL_RISK_KEYWORDS = {
    "high_risk": [
        "verify your account", "urgent action required", "account suspended",
        "confirm your identity", "login immediately", "reset your password now",
        "unauthorized access detected", "click below to secure", "final warning",
        "security alert", "update your payment details", "provide your otp",
        "enter your credentials", "account locked", "suspicious activity detected",
        "claim your reward now", "limited time offer", "act now"
    ],
    "medium_risk": [
        "verify", "update details", "login to continue", "security check",
        "account update", "important notice", "password reset", "confirm information",
        "billing issue", "unusual activity", "please respond", "take action",
        "account review", "notification", "service interruption", "limited access",
        "attention required"
    ],
    "low_risk": [
        "hello", "thank you", "your request", "account summary", "transaction details",
        "invoice attached", "meeting schedule", "customer support", "update available",
        "information", "welcome", "confirmation", "details enclosed", "service update",
        "newsletter", "reminder", "subscription", "report"
    ]
}

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret')

# Flask-Mail Configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

mail = Mail(app)

# Initialize Login Manager
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# MongoDB Configuration
MONGO_URI = os.getenv('MONGO_URI')

# Initialize MongoDB client
try:
    client = MongoClient(MONGO_URI, server_api=ServerApi('1'))
    # Send a ping to confirm a successful connection
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
    
    # Select the database
    db = client.get_database('phishguard_db') # Or whatever name you want for the database
    analysis_collection = db.analyzed_emails
    users_collection = db.users
    
except Exception as e:
    print(f"Error connecting to MongoDB: {e}")
    db = None
    analysis_collection = None
    users_collection = None

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.name = user_data.get('name', '')
        self.email = user_data.get('email', '')

# Gemini Configuration
GOOGLE_API_KEY = os.getenv('GOOGLE_API_KEY')
if GOOGLE_API_KEY:
    genai.configure(api_key=GOOGLE_API_KEY)
    # Using gemini-2.0-flash which is available in this environment
    model = genai.GenerativeModel('gemini-2.0-flash')
else:
    model = None
    print("WARNING: GOOGLE_API_KEY not found in environment. AI features will be disabled.")

@login_manager.user_loader
def load_user(user_id):
    from bson.objectid import ObjectId
    if users_collection is None:
        return None
    user_data = users_collection.find_one({'_id': ObjectId(user_id)})
    if user_data:
        return User(user_data)
    return None

@login_manager.unauthorized_handler
def unauthorized():
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Authentication required'}), 401
    flash('Please log in to access this page.', 'warning')
    return redirect(url_for('login'))

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def send_otp_email(email, otp):
    msg = Message('Your PhishGuard AI Verification Code',
                  recipients=[email])
    msg.body = f'''Hello,

Thank you for signing up for PhishGuard AI. 

Your verification code is: {otp}

This code will expire in 10 minutes. Please do not share this code with anyone.

Securely,
The PhishGuard Team'''
    try:
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

@app.route('/')
def index():
    return render_template('index.html', active_page='home')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        if users_collection is None:
            flash('Database connection error. Please try again later.', 'error')
            return render_template('login.html')
            
        email = request.form.get('email')
        password = request.form.get('password')
        
        user_data = users_collection.find_one({'email': email})
        
        if user_data and check_password_hash(user_data['password'], password):
            user = User(user_data)
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password', 'error')
            
    return render_template('login.html', active_page='login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        if users_collection is None:
            flash('Database connection error. Please try again later.', 'error')
            return render_template('register.html')
            
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Check if user already exists
        if users_collection.find_one({'email': email}):
            flash('Email address already exists', 'error')
            return redirect(url_for('register'))
            
        # Store data in session for verification
        otp = generate_otp()
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        
        session['pending_user'] = {
            'name': name,
            'email': email,
            'password': hashed_password,
            'otp': otp,
            'timestamp': datetime.now().timestamp()
        }
        
        if send_otp_email(email, otp):
            flash('A verification code has been sent to your email.', 'info')
            return redirect(url_for('verify_otp'))
        else:
            flash('Error sending verification email. Please check your SMTP settings.', 'error')
            
    return render_template('register.html', active_page='register')

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if 'pending_user' not in session:
        return redirect(url_for('register'))
        
    if request.method == 'POST':
        entered_otp = request.form.get('otp')
        pending_data = session['pending_user']
        
        # Session expiry check (10 mins)
        if datetime.now().timestamp() - pending_data['timestamp'] > 600:
            session.pop('pending_user', None)
            flash('Verification code expired. Please sign up again.', 'error')
            return redirect(url_for('register'))
            
        if entered_otp == pending_data['otp']:
            # OTP match, save user to DB
            users_collection.insert_one({
                'name': pending_data['name'],
                'email': pending_data['email'],
                'password': pending_data['password']
            })
            session.pop('pending_user', None)
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid verification code. Please try again.', 'error')
            
    return render_template('verify_otp.html', active_page='register')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    if analysis_collection is None:
        flash("Database connection error.", "error")
        return redirect(url_for('index'))
        
    # Fetch user history for stats
    user_history = list(analysis_collection.find({'user_id': current_user.id}))
    
    # Calculate stats
    total_count = len(user_history)
    phishing_count = sum(1 for item in user_history if item.get('status') == 'phishing')
    safe_count = total_count - phishing_count
    
    # Prepare chart data (last 7 days or all)
    return render_template(
        'dashboard.html', 
        total_count=total_count,
        phishing_count=phishing_count,
        safe_count=safe_count,
        active_page='dashboard'
    )

@app.route('/history')
@login_required
def history():
    if analysis_collection is None:
        flash("Database connection error.", "error")
        return redirect(url_for('index'))
        
    # Fetch all analyses for current user, sorted newest first
    user_history = list(analysis_collection.find({'user_id': current_user.id}).sort('_id', -1))
    
    # Calculate stats
    total_count = len(user_history)
    phishing_count = sum(1 for item in user_history if item.get('status') == 'phishing')
    safe_count = total_count - phishing_count
    
    return render_template(
        'history.html', 
        history=user_history,
        total_count=total_count,
        phishing_count=phishing_count,
        safe_count=safe_count,
        active_page='history'
    )

@app.route('/profile')
@login_required
def profile():
    if analysis_collection is None:
        total_count = 0
        phishing_count = 0
        safe_count = 0
    else:
        user_history = list(analysis_collection.find({'user_id': current_user.id}))
        total_count = len(user_history)
        phishing_count = sum(1 for item in user_history if item.get('status') == 'phishing')
        safe_count = total_count - phishing_count

    return render_template(
        'profile.html',
        total_count=total_count,
        phishing_count=phishing_count,
        safe_count=safe_count,
        active_page='profile'
    )

@app.route('/api/analyze', methods=['POST'])
@login_required
def save_analysis():
    if analysis_collection is None:
         return jsonify({'error': 'Database connection failed'}), 500
         
    data = request.json
    if not data:
        return jsonify({'error': 'No data provided'}), 400
        
    try:
        content = data.get('content', '')
        sender_email = data.get('sender_email', '')
        
        # --- Advanced Local Keyword Scoring ---
        local_score = 0
        text_lower = content.lower()
        
        # High risk hits (capped at 50 for local)
        high_hits = 0
        for word in INTERNAL_RISK_KEYWORDS["high_risk"]:
            if word in text_lower:
                high_hits += 1
                local_score += 15
        
        # Medium risk hits (limited contribution)
        med_hits = 0
        for word in INTERNAL_RISK_KEYWORDS["medium_risk"]:
            if word in text_lower:
                med_hits += 1
                if med_hits <= 3:
                    local_score += 5
                else:
                    local_score += 1
        
        # Safe word buffer (stronger deduction)
        # Using both original safe keywords and provided safe_words
        safe_keywords_all = [
            "no need to share password", "we will never ask for otp", "official website",
            "secure login via app", "contact our support team", "privacy policy",
            "terms and conditions", "customer care", "verified sender", "bank branch visit",
            "support@company.com", "help center", "unsubscribe option"
        ] + TRUSTED_DATA["safe_words"]

        for word in safe_keywords_all:
            if word in text_lower:
                local_score -= 20 # Increased deduction to prioritize safe words

        # Initialize risk score with local findings (clamped between 0 and 100)
        risk_score = max(0, min(local_score, 100))
        
        # --- Trusted Source Checks ---
        is_trusted_sender = sender_email.lower() in [e.lower() for e in TRUSTED_DATA["trusted_emails"]]
        
        # Extract URLs
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', content)
        
        has_trusted_domain = False
        for url in urls:
            for trusted_domain in TRUSTED_DATA["trusted_domains"]:
                if trusted_domain.lower() in url.lower():
                    has_trusted_domain = True
                    break
        
        # Trusted sender/domain significantly reduces risk
        if is_trusted_sender:
            risk_score = max(0, risk_score - 50)
        if has_trusted_domain:
            risk_score = max(0, risk_score - 30)

        # Local trust for school emails
        if sender_email.endswith('.ac.in') or sender_email.endswith('.edu.in') or sender_email.endswith('.edu'):
            risk_score = max(0, risk_score - 20)
            
        final_status = 'safe'
        confidence = 0
        reasons = []
        highlight_map = {'suspicious': [], 'trusted': []}

        # Pre-extract structural features for the prompt
        has_ip = any(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', u) for u in urls)
        ssl_missing = any(not u.startswith('https') for u in urls)
        long_url = any(len(u) > 60 for u in urls)
        
        # --- Gemini AI Analysis Integration ---
        if model:
            try:
                prompt = f"""
Analyze this message. Is it a scam or safe? Use very easy words.

SENDER: {sender_email if sender_email else 'Unknown'}
MESSAGE: {content}

CHECKLIST FOR YOU:
- Links found: {len(urls)}
- Uses numbers instead of a name in link: {'Yes' if has_ip else 'No'}
- Link is not locked (no https): {'Yes' if ssl_missing else 'No'}
- Link is too long or weird: {'Yes' if long_url else 'No'}
- Sender is a TRUSTED company email: {'Yes' if is_trusted_sender else 'No'}
- Includes a TRUSTED company domain/link: {'Yes' if has_trusted_domain else 'No'}

YOUR GOAL:
1. Give a score from 0 to 100. IMPORTANT: If it is definitely a scam, the score MUST be between 85 and 100.
2. Status: "phishing" (scam) or "safe" (okay).
3. Two simple points to explain why.
4. DO NOT use big words like 'Structural', 'Neural', 'Heuristic', 'Credential', or 'Mismatched'.
5. Talk like you are helping a friend.
6. If the sender or domain is TRUSTED, you should highly favor a "safe" status unless the content is extremely suspicious.

STRICT DETECTION RULES:
- If someone asks for money, passwords, or OTP, it is a SCAM.
- If it says "Your account will be deleted" or "Hurry up!", it is likely a SCAM.
- If a link doesn't start with "https" or has many numbers, it is a SCAM.
- If it is from a school (.ac.in or .edu.in) and looks normal, it is SAFE.
- If it is from a TRUSTED sender or has a TRUSTED domain, it is ALMOST ALWAYS SAFE. These are verified corporate accounts. Do not flag them as phishing unless you are 100% sure the account is compromised.
- If it's a receipt, bill, or OTP request from a TRUSTED company, it is SAFE.

JSON FORMAT ONLY:
{{
  "risk_score": number,
  "status": "phishing" | "safe",
  "confidence": 99,
  "reasons": [
    {{
      "text": "What we found",
      "explanation": "• Point 1 in very easy words\n• Point 2 in very easy words",
      "category": "keywords",
      "isWarning": boolean
    }},
    {{
      "text": "Check Result",
      "explanation": "• Point 1 in very easy words\n• Point 2 in very easy words",
      "category": "urls",
      "isWarning": boolean
    }}
  ],
  "highlights": {{
    "suspicious": ["scary word"],
    "trusted": ["good word"]
  }}
}}
"""
                
                response = model.generate_content(prompt)
                
                # Check for empty response or safety blocks
                if not response.candidates:
                    raise ValueError("AI returned no candidates (possibly blocked by safety filters)")
                
                if not response.text:
                    raise ValueError("AI returned empty text")

                # Robust JSON extraction using regex
                resp_text = response.text
                print(f"DEBUG: AI Raw Response: {resp_text}")
                
                json_match = re.search(r'\{.*\}', resp_text, re.DOTALL)
                if json_match:
                    resp_text = json_match.group(0)
                else:
                    raise ValueError("No JSON block found in AI response")
                
                ai_data = json.loads(resp_text)
                
                ai_risk = ai_data.get('risk_score', 0)
                ai_status = ai_data.get('status', 'safe')
                confidence = ai_data.get('confidence', 0)
                reasons = ai_data.get('reasons', [])
                highlight_map = ai_data.get('highlights', {'suspicious': [], 'trusted': []})

                # --- SMART BLENDING ---
                # If high-confidence AI says it's safe, trust it more than low/med local keywords
                if ai_status == 'safe' and confidence > 90:
                    # AI "Veto": Reduce local score if it's below a critical threshold
                    if risk_score < 45:
                        risk_score = (risk_score * 0.4) + (ai_risk * 0.6)
                    else:
                        risk_score = (risk_score * 0.6) + (ai_risk * 0.4)
                else:
                    # Normal blending: pick the more cautious score
                    risk_score = max(risk_score, ai_risk)
                
                final_status = ai_status
                
            except Exception as ai_err:
                error_detail = str(ai_err)
                print(f"Gemini Analysis failed: {error_detail}")
                
                # Fallback with friendly info
                # Keep the risk score from keywords if it was higher
                risk_score = max(local_score, 15)
                final_status = 'safe'
                confidence = 50
                if not reasons:
                    reasons = [
                        {
                            'text': 'Preliminary Check', 
                            'isWarning': False, 
                            'explanation': '• This message looks mostly okay on the surface.\n• Be careful before clicking any links.', 
                            'category': 'trusted'
                        },
                        {
                            'text': 'Automated Scan',
                            'isWarning': False,
                            'explanation': '• No immediate danger found by our basic scan.\n• Always double check unknown senders.',
                            'category': 'trusted'
                        }
                    ]
                highlight_map = {'suspicious': [], 'trusted': []}
        else:
            # Fallback for when API key is missing
            # --- Local Keyword Safety Net ---
            scary_words = ['otp', 'password', 'bank', 'transfer', 'urgent', 'winner', 'lottery', 'reward', 'verify', 'account']
            found_scary = [w for w in scary_words if w in content.lower()]
            
            # Initial risk boost based on content
            if found_scary:
                risk_score = 30 + (len(found_scary) * 5)
            else:
                risk_score = 0
            
            # Additional local adjustments for fallback
            if is_trusted_sender:
                risk_score = max(0, risk_score - 40)
            if has_trusted_domain:
                risk_score = max(0, risk_score - 20)
                
            final_status = 'safe'
            confidence = 0
            reasons = []
            if found_scary and risk_score >= 40:
                reasons.append({
                    'text': 'Keyword Alert',
                    'isWarning': True,
                    'explanation': f'• Found suspicious words like: {", ".join(found_scary)}.\n• Be extra careful with this message.',
                    'category': 'keywords'
                })
                final_status = 'phishing' if risk_score >= 55 else 'safe'
            else:
                safe_reason = "This sender and its links are verified as trusted." if (is_trusted_sender or has_trusted_domain) else "No immediate danger found by our basic scan."
                reasons.append({
                    'text': 'Checking done', 
                    'isWarning': False, 
                    'explanation': f'• {safe_reason}\n• This email is safe to read.', 
                    'category': 'trusted'
                })
                reasons.append({
                    'text': 'Good message',
                    'isWarning': False,
                    'explanation': '• The content looks clean and safe.\n• No login tricks found here.',
                    'category': 'trusted'
                })
            highlight_map = {'suspicious': [], 'trusted': []}

        # --- Local Similarity check logic (Cross-reference with local DB) ---
        similar_spam_alerts = []
        # Only check similarity for longer messages to avoid generic false positives
        if len(content) > 20:
            try:
                past_phishing = list(analysis_collection.find({'status': 'phishing'}))
                if past_phishing:
                    corpus = [p['content'] for p in past_phishing]
                    corpus.append(content)
                    vectorizer = TfidfVectorizer(stop_words='english')
                    tfidf_matrix = vectorizer.fit_transform(corpus)
                    cosine_sim = cosine_similarity(tfidf_matrix[-1], tfidf_matrix[:-1]).flatten()
                    top_indices = cosine_sim.argsort()[-3:][::-1]
                    
                    for idx in top_indices:
                        sim_score = cosine_sim[idx] * 100
                        # Increased threshold to 85% for similarity matches
                        if sim_score > 85:
                            past_record = past_phishing[idx]
                            similar_spam_alerts.append({
                                'score': round(sim_score, 1),
                                'preview': past_record['content'][:50] + '...'
                            })
                            
                            # EXCLUSION: Never boost for similarity if it's a trusted source, 
                            # unless it's a 100% perfect match (meaning the actual email was previously seen as phishing)
                            if not (is_trusted_sender or has_trusted_domain):
                                if risk_score < 80: 
                                    risk_score = max(risk_score + 25, 80)
                                else:
                                    risk_score = min(risk_score + 10, 100)
                            elif sim_score > 98:
                                # Very rare edge case for compromised accounts
                                risk_score = max(risk_score, 85)
            except Exception as sim_err:
                print(f"Similarity computation failed: {sim_err}")

        # Final adjustments
        # If score is very high, it's phishing. If very low, it's safe.
        # Otherwise, we trust the AI status which was set earlier.
        if risk_score >= 85: 
            final_status = 'phishing'
        elif risk_score < 45: 
            final_status = 'safe'
        # Else: keep final_status from AI
        
        # Guard against over-sensitive phishing flags
        if final_status == 'phishing' and risk_score < 75: 
            risk_score = 75
        
        # Ensure trusted sources stay safe even with some risk keywords
        # AGGRESSIVE OVERRIDE: Cap risk for verified entities
        if (is_trusted_sender or has_trusted_domain):
            if risk_score < 95: # Unless it's an extreme outlier
                risk_score = min(risk_score, 35) # Hard cap at 35 (well into safe territory)
                final_status = 'safe'
            elif ai_status == 'safe' or confidence < 95:
                # Even if score is high, if AI is unsure, favor safety for trusted entities
                risk_score = 40
                final_status = 'safe'
            
        if risk_score > 99: risk_score = 99
        if risk_score < 1: risk_score = 1


        # --- End Python Logic ---

        # Prepare document to be saved
        document = {
            'user_id': current_user.id,
            'sender_email': sender_email,
            'content': content,
            'risk_score': risk_score,
            'status': final_status,
            'confidence': confidence,
            'reasons': reasons,
            'highlights': highlight_map,
            'is_trusted': is_trusted_sender or has_trusted_domain,
            'trust_type': 'sender' if is_trusted_sender else 'domain' if has_trusted_domain else None,
            'timestamp': data.get('timestamp')
        }
        
        # Insert into MongoDB
        result = analysis_collection.insert_one(document)
        
        return jsonify({
            'success': True, 
            'message': 'Analysis completed',
            'id': str(result.inserted_id),
            'risk_score': risk_score,
            'status': final_status,
            'confidence': confidence,
            'reasons': reasons,
            'similar_spam': similar_spam_alerts,
            'highlights': highlight_map,
            'is_trusted': is_trusted_sender or has_trusted_domain,
            'trust_type': 'sender' if is_trusted_sender else 'domain' if has_trusted_domain else None
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
