import sqlite3
import os
from flask import Flask, render_template, request, redirect, session, g, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__, template_folder='static_frontend')
# Secure key for sessions
app.secret_key = os.urandom(24) 
DATABASE = 'donors.db'

# --- Database Management ---
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # Access columns by name
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                pincode TEXT NOT NULL,
                blood_group TEXT,
                phone TEXT,
                is_available INTEGER DEFAULT 0,
                history TEXT
            )
        """)
        db.commit()

# --- Security: Runs before every request ---
@app.before_request
def check_login():
    public_routes = ['login', 'signup', 'landing', 'static']
    if 'user_id' not in session and request.endpoint not in public_routes:
        return redirect("/login")

# --- Routes ---

@app.route("/")
def landing():
    """Landing Page (Unauthenticated)"""
    if 'user_id' in session:
        return redirect("/dashboard")
    return render_template("index.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    """Sign-Up Page"""
    if request.method == "POST":
        full_name = request.form.get("full_name").strip()
        email = request.form.get("email").strip()
        pwd = request.form.get("password")
        pincode = request.form.get("pincode").strip()
        blood_group = request.form.get("blood_group")
        
        if full_name and email and pwd and pincode and blood_group:
            hashed_pwd = generate_password_hash(pwd)
            db = get_db()
            try:
                db.execute("INSERT INTO users (full_name, email, password, pincode, blood_group) VALUES (?, ?, ?, ?, ?)", 
                           (full_name, email, hashed_pwd, pincode, blood_group))
                db.commit()
                flash("Account created successfully! Please log in.", "success")
                return redirect("/login")
            except sqlite3.IntegrityError:
                flash("Email already exists! Please use a different email or log in.", "danger")
        else:
            flash("All fields are required!", "warning")
    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Login Page"""
    if request.method == "POST":
        email = request.form.get("email")
        pwd = request.form.get("password")
        
        db = get_db()
        user_data = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        
        if user_data and check_password_hash(user_data['password'], pwd):
            session['user_id'] = user_data['id']
            session['full_name'] = user_data['full_name']
            return redirect("/dashboard")
        else:
            flash("Invalid Credentials", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    """Donor Dashboard"""
    db = get_db()
    if request.method == "POST":
        blood_group = request.form.get("blood_group")
        phone = request.form.get("phone")
        is_available = 1 if request.form.get("is_available") else 0
        history = request.form.get("history")
        
        db.execute("""
            UPDATE users SET blood_group=?, phone=?, is_available=?, history=?
            WHERE id=?
        """, (blood_group, phone, is_available, history, session['user_id']))
        db.commit()
        flash("Dashboard updated successfully!", "success")
        
    user_data = db.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    return render_template("dashboard.html", user=user_data)

@app.route("/search", methods=["GET", "POST"])
def search():
    """Authenticated Search Page"""
    db = get_db()
    donors = None  # None indicates search wasn't performed yet
    
    if request.method == "POST":
        blood = request.form.get("blood")
        pincode = request.form.get("pincode")
        
        query = "SELECT * FROM users WHERE is_available = 1"
        params = []
        if blood:
            query += " AND blood_group = ?"
            params.append(blood)
        if pincode:
            query += " AND pincode = ?"
            params.append(pincode)
            
        donors = db.execute(query, params).fetchall()
    
    return render_template("search.html", donors=donors)

@app.route("/api/donors", methods=["GET"])
def api_donors():
    db = get_db()
    pincode = request.args.get("pincode")
    blood_group = request.args.get("bloodGroup")
    
    query = "SELECT * FROM users WHERE is_available = 1"
    params = []
    
    if pincode:
        query += " AND pincode = ?"
        params.append(pincode)
    if blood_group:
        query += " AND blood_group = ?"
        params.append(blood_group)
        
    donors = db.execute(query, params).fetchall()
    
    # Convert sqlite3.Row to dict
    results = []
    for d in donors:
        results.append({
            "fullName": d["full_name"],
            "bloodGroup": d["blood_group"],
            "pincode": d["pincode"],
            "email": d["email"],
            "note": d["history"]
        })
    return jsonify(results)

if __name__ == "__main__":
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
