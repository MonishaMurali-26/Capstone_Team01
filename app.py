from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from database import db, User  # Import database and User model

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vehicle_management.db'
app.config['SECRET_KEY'] = 'vehicle_management_secret_key'
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "warning"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember = 'remember' in request.form
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user, remember=remember)
            flash('Login successful! Welcome to Vehicle Management System.', 'success')
            
            # Get the next page from the session
            next_page = session.get('next', None)
            if next_page:
                session.pop('next', None)
                return redirect(next_page)
                
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password. Please try again.', 'error')
    
    return render_template('login.html', title="Login - Vehicle Management System")

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Validate input
        if len(username) < 3:
            flash('Username must be at least 3 characters long.', 'error')
            return render_template('signup.html', title="Sign Up - Vehicle Management System")
            
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return render_template('signup.html', title="Sign Up - Vehicle Management System")
            
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('signup.html', title="Sign Up - Vehicle Management System")
        
        existing_user = User.query.filter_by(username=username).first()
        
        if existing_user:
            flash('Username already exists. Please choose another username.', 'error')
        else:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            new_user = User(username=username, password=hashed_password, role='user')
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully! You can now log in.', 'success')
            return redirect(url_for('login'))
    
    return render_template('signup.html', title="Sign Up - Vehicle Management System")

@app.route('/dashboard')
@login_required
def dashboard():
    # Pass current_user.role to the template
    return render_template('dashboard.html', 
                          title="Dashboard - Vehicle Management System",
                          username=current_user.username,
                          role=current_user.role)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.errorhandler(404)
def page_not_found(e):
    flash('Page not found.', 'error')
    return redirect(url_for('dashboard'))

@app.errorhandler(500)
def internal_server_error(e):
    flash('An unexpected error occurred. Please try again later.', 'error')
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)