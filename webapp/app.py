#!/usr/bin/env python3
"""
Vulnerable Flask Web Application for Falco Testing
Intentionally insecure - no input sanitization
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import os
import subprocess
import logging
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'insecure-secret-key-for-testing'

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# In-memory fake database
items_db = {
    1: {'id': 1, 'name': 'Laptop', 'description': 'Gaming laptop', 'price': 999.99},
    2: {'id': 2, 'name': 'Mouse', 'description': 'Wireless mouse', 'price': 29.99},
    3: {'id': 3, 'name': 'Keyboard', 'description': 'Mechanical keyboard', 'price': 79.99},
}
next_id = 4

# Fake user database
users_db = {
    'admin': 'admin123',
    'user': 'password123',
}

@app.route('/')
def home():
    """Home page with search bar"""
    logger.info(f"Home page accessed from {request.remote_addr}")
    return render_template('home.html')

@app.route('/items')
def list_items():
    """List all items from in-memory store"""
    logger.info(f"Items list accessed from {request.remote_addr}")
    return render_template('items.html', items=list(items_db.values()))

@app.route('/item/<id>')
def item_details(id):
    """Item details - vulnerable to path traversal"""
    logger.info(f"Item details accessed: {id} from {request.remote_addr}")
    
    # VULNERABLE: No validation, could be used for path traversal
    try:
        item_id = int(id)
        if item_id in items_db:
            return render_template('item_detail.html', item=items_db[item_id])
        else:
            # VULNERABLE: Try to read file if item not found
            # This is intentionally vulnerable for path traversal attacks
            if '..' in str(id):
                try:
                    # Dangerous: attempting to read files
                    with open(id, 'r') as f:
                        content = f.read()
                    return f"File content: {content[:500]}"
                except:
                    pass
            return f"Item {id} not found", 404
    except ValueError:
        # VULNERABLE: Could be path traversal attempt
        return f"Invalid item ID: {id}", 400

@app.route('/add', methods=['GET', 'POST'])
def add_item():
    """Add item form - vulnerable to command injection"""
    if request.method == 'POST':
        name = request.form.get('name', '')
        description = request.form.get('description', '')
        price = request.form.get('price', '0')
        
        logger.info(f"Adding item: {name} from {request.remote_addr}")
        
        # VULNERABLE: No input sanitization
        global next_id
        items_db[next_id] = {
            'id': next_id,
            'name': name,
            'description': description,
            'price': float(price) if price.replace('.', '').isdigit() else 0.0
        }
        next_id += 1
        
        # VULNERABLE: Command injection possibility
        # If name contains shell commands, they might be executed
        if ';' in name or '|' in name or '`' in name:
            try:
                # Dangerous: executing shell commands
                result = subprocess.run(
                    f"echo Item added: {name}",
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                logger.warning(f"Command executed: {result.stdout}")
            except Exception as e:
                logger.error(f"Command execution error: {e}")
        
        return redirect(url_for('list_items'))
    
    return render_template('add_item.html')

@app.route('/search')
def search():
    """Search endpoint - vulnerable to SQL injection style attacks"""
    query = request.args.get('q', '')
    logger.info(f"Search query: {query} from {request.remote_addr}")
    
    # VULNERABLE: No input sanitization, SQL injection patterns
    # Simulating a fake SQL-like search
    results = []
    
    # Intentionally vulnerable search logic
    if query:
        # Simulating SQL-like behavior
        if "' OR '1'='1" in query or "1=1" in query:
            # Would return all items in real SQL injection
            results = list(items_db.values())
        else:
            # Normal search (but still vulnerable)
            for item in items_db.values():
                if query.lower() in item['name'].lower() or query.lower() in item['description'].lower():
                    results.append(item)
    
    return render_template('search_results.html', query=query, results=results)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Simple fake login form - vulnerable to brute force"""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        logger.info(f"Login attempt: {username} from {request.remote_addr}")
        
        # VULNERABLE: No rate limiting, vulnerable to brute force
        if username in users_db and users_db[username] == password:
            session['username'] = username
            session['logged_in'] = True
            return redirect(url_for('home'))
        else:
            return render_template('login.html', error='Invalid credentials')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout endpoint"""
    session.clear()
    return redirect(url_for('home'))

@app.route('/api/execute', methods=['POST'])
def execute_command():
    """API endpoint vulnerable to command injection"""
    data = request.get_json() or {}
    command = data.get('command', '')
    
    logger.warning(f"Command execution request: {command} from {request.remote_addr}")
    
    # VULNERABLE: Direct command execution
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=5
        )
        return jsonify({
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

