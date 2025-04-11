<<<<<<< HEAD
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
=======
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date
import os
from functools import wraps
import pandas as pd
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
from io import BytesIO
import base64

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24).hex()  # Secure random secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vehicle_management.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Models (unchanged)
class User(db.Model):
    __tablename__ = "users"
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.Text, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    role = db.Column(db.String(10), nullable=False)  # 'Admin' or 'User'
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    fuel_entries = db.relationship('FuelUsage', backref='user', lazy=True)
    maintenance_logs = db.relationship('Maintenance', backref='user', lazy=True)
    generated_reports = db.relationship('Report', backref='admin', lazy=True)
    logs = db.relationship('Log', backref='admin', lazy=True)

class Vehicle(db.Model):
    __tablename__ = "vehicles"
    vehicle_id = db.Column(db.Integer, primary_key=True)
    vin = db.Column(db.String(50), unique=True, nullable=False)
    mileage = db.Column(db.Integer, nullable=False)
    fuel_type = db.Column(db.String(20), nullable=False)
    purchase_date = db.Column(db.Date, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    fuel_entries = db.relationship('FuelUsage', backref='vehicle', lazy=True)
    maintenance_logs = db.relationship('Maintenance', backref='vehicle', lazy=True)
    alerts = db.relationship('Alert', backref='vehicle', lazy=True)

class FuelUsage(db.Model):
    __tablename__ = "fuel_usage"
    fuel_id = db.Column(db.Integer, primary_key=True)
    vehicle_id = db.Column(db.Integer, db.ForeignKey('vehicles.vehicle_id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=True)
    fuel_quantity = db.Column(db.Float, nullable=False)
    fuel_cost = db.Column(db.Float, nullable=False)
    mileage_at_refuel = db.Column(db.Integer, nullable=False)
    fuel_date = db.Column(db.DateTime, default=datetime.utcnow)

class Maintenance(db.Model):
    __tablename__ = "maintenance"
    maintenance_id = db.Column(db.Integer, primary_key=True)
    vehicle_id = db.Column(db.Integer, db.ForeignKey('vehicles.vehicle_id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=True)
    service_type = db.Column(db.String(50), nullable=False)
    service_cost = db.Column(db.Float, nullable=False)
    service_date = db.Column(db.Date, nullable=False)
    comments = db.Column(db.Text)

class Report(db.Model):
    __tablename__ = "reports"
    report_id = db.Column(db.Integer, primary_key=True)
    report_type = db.Column(db.String(10), nullable=False)  # 'Monthly' or 'Annual'
    generated_by = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=True)
    generated_at = db.Column(db.DateTime, default=datetime.utcnow)
    report_file_path = db.Column(db.Text, nullable=False)

class Log(db.Model):
    __tablename__ = "logs"
    log_id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    table_name = db.Column(db.String(50), nullable=False)
    record_id = db.Column(db.Integer, nullable=False)
    action_timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Alert(db.Model):
    __tablename__ = "alerts"
    alert_id = db.Column(db.Integer, primary_key=True)
    vehicle_id = db.Column(db.Integer, db.ForeignKey('vehicles.vehicle_id'), nullable=False)
    alert_message = db.Column(db.Text, nullable=False)
    alert_type = db.Column(db.String(20), nullable=False)  # 'Fuel Usage', 'Maintenance Overdue', 'Missing Data'
    is_resolved = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Database Initialization
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            password_hash=generate_password_hash('admin123'),
            email='admin@example.com',
            role='Admin',
            is_active=True,
            created_at=datetime.utcnow()
        )
        db.session.add(admin)
        db.session.commit()
        print("Admin user 'admin' created with password 'admin123'.")

# Utility function for logs
def create_log(admin_id, action, table_name, record_id):
    log = Log(admin_id=admin_id, action=action, table_name=table_name, record_id=record_id)
    db.session.add(log)
    db.session.commit()

# Decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'danger')
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if user.role != 'Admin':
            flash('You do not have permission to access this page', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Routes (only updating the problematic ones)
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password_hash, password):
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))
        if not user.is_active:
            flash('Your account is deactivated. Please contact an administrator.', 'danger')
            return redirect(url_for('login'))
        session['user_id'] = user.user_id
        session['username'] = user.username
        session['role'] = user.role
        flash(f'Welcome back, {user.username}!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    vehicles_count = Vehicle.query.filter_by(is_active=True).count()
    recent_fuel = db.session.query(FuelUsage, Vehicle).join(
        Vehicle, FuelUsage.vehicle_id == Vehicle.vehicle_id
    ).order_by(FuelUsage.fuel_date.desc()).limit(5).all()
    recent_maintenance = db.session.query(Maintenance, Vehicle).join(
        Vehicle, Maintenance.vehicle_id == Vehicle.vehicle_id
    ).order_by(Maintenance.service_date.desc()).limit(5).all()
    alerts = [] if user.role != 'Admin' else Alert.query.filter_by(is_resolved=False).order_by(Alert.created_at.desc()).limit(5).all()
    return render_template(
        'dashboard.html',
        user=user,
        vehicles_count=vehicles_count,
        recent_fuel=recent_fuel,
        recent_maintenance=recent_maintenance,
        alerts=alerts
    )

# Fuel Management Routes
@app.route('/fuel')
@login_required
def fuel():
    if session['role'] == 'Admin':
        fuel_entries = db.session.query(FuelUsage, Vehicle, User).join(
            Vehicle, FuelUsage.vehicle_id == Vehicle.vehicle_id
        ).join(User, FuelUsage.user_id == User.user_id).order_by(FuelUsage.fuel_date.desc()).all()
    else:
        fuel_entries = db.session.query(FuelUsage, Vehicle, User).join(
            Vehicle, FuelUsage.vehicle_id == Vehicle.vehicle_id
        ).join(User, FuelUsage.user_id == User.user_id).filter(
            FuelUsage.user_id == session['user_id']
        ).order_by(FuelUsage.fuel_date.desc()).all()
    return render_template('fuel.html', fuel_entries=fuel_entries)

@app.route('/fuel/add', methods=['GET', 'POST'])
@login_required
def add_fuel():
    vehicles = Vehicle.query.filter_by(is_active=True).all()
    if request.method == 'POST':
        vehicle_id = request.form.get('vehicle_id')
        fuel_quantity = request.form.get('fuel_quantity')
        fuel_cost = request.form.get('fuel_cost')
        mileage_at_refuel = request.form.get('mileage_at_refuel')
        fuel_date = request.form.get('fuel_date') or datetime.utcnow().strftime('%Y-%m-%d')
        
        if not all([vehicle_id, fuel_quantity, fuel_cost, mileage_at_refuel]):
            flash('All fields are required', 'danger')
            return redirect(url_for('add_fuel'))
        
        try:
            vehicle = Vehicle.query.get(vehicle_id)
            mileage_at_refuel = int(mileage_at_refuel)
            if mileage_at_refuel < vehicle.mileage:
                flash('Refuel mileage cannot be less than the current vehicle mileage', 'danger')
                return redirect(url_for('add_fuel'))
            
            fuel_entry = FuelUsage(
                vehicle_id=vehicle_id,
                user_id=session['user_id'],
                fuel_quantity=float(fuel_quantity),
                fuel_cost=float(fuel_cost),
                mileage_at_refuel=mileage_at_refuel,
                fuel_date=datetime.strptime(fuel_date, '%Y-%m-%d')
            )
            vehicle.mileage = mileage_at_refuel
            db.session.add(fuel_entry)
            db.session.commit()
            flash('Fuel entry added successfully', 'success')
            return redirect(url_for('fuel'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {str(e)}', 'danger')
            return redirect(url_for('add_fuel'))
    
    # Pass current date to template
    return render_template('add_fuel.html', vehicles=vehicles, current_date=datetime.utcnow().strftime('%Y-%m-%d'))

# Maintenance Management Routes
@app.route('/maintenance')
@login_required
def maintenance():
    if session['role'] == 'Admin':
        maintenance_entries = db.session.query(Maintenance, Vehicle, User).join(
            Vehicle, Maintenance.vehicle_id == Vehicle.vehicle_id
        ).join(User, Maintenance.user_id == User.user_id).order_by(Maintenance.service_date.desc()).all()
    else:
        maintenance_entries = db.session.query(Maintenance, Vehicle, User).join(
            Vehicle, Maintenance.vehicle_id == Vehicle.vehicle_id
        ).join(User, Maintenance.user_id == User.user_id).filter(
            Maintenance.user_id == session['user_id']
        ).order_by(Maintenance.service_date.desc()).all()
    return render_template('maintenance.html', maintenance_entries=maintenance_entries)

@app.route('/maintenance/add', methods=['GET', 'POST'])
@login_required
def add_maintenance():
    vehicles = Vehicle.query.filter_by(is_active=True).all()
    if request.method == 'POST':
        vehicle_id = request.form.get('vehicle_id')
        service_type = request.form.get('service_type')
        service_cost = request.form.get('service_cost')
        service_date = request.form.get('service_date')
        comments = request.form.get('comments')
        
        # Handle custom service type from "Other" option
        if service_type == 'Other' and 'other_service_type' in request.form:
            service_type = request.form.get('other_service_type')
        
        if not all([vehicle_id, service_type, service_cost, service_date]):
            flash('All fields except comments are required', 'danger')
            return redirect(url_for('add_maintenance'))
        
        try:
            maintenance_entry = Maintenance(
                vehicle_id=vehicle_id,
                user_id=session['user_id'],
                service_type=service_type,
                service_cost=float(service_cost),
                service_date=datetime.strptime(service_date, '%Y-%m-%d').date(),
                comments=comments
            )
            db.session.add(maintenance_entry)
            db.session.commit()
            flash('Maintenance entry added successfully', 'success')
            return redirect(url_for('maintenance'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {str(e)}', 'danger')
            return redirect(url_for('add_maintenance'))
    
    # Pass current date to template
    return render_template('add_maintenance.html', vehicles=vehicles, current_date=datetime.utcnow().strftime('%Y-%m-%d'))

# Other Routes (unchanged for brevity, but included for completeness)
@app.route('/vehicles')
@login_required
def vehicles():
    vehicles = Vehicle.query.all()
    return render_template('vehicles.html', vehicles=vehicles)

@app.route('/vehicles/add', methods=['GET', 'POST'])
@login_required
def add_vehicle():
    if request.method == 'POST':
        vin = request.form.get('vin')
        mileage = request.form.get('mileage')
        fuel_type = request.form.get('fuel_type')
        purchase_date = request.form.get('purchase_date')
        if not all([vin, mileage, fuel_type, purchase_date]):
            flash('All fields are required', 'danger')
            return redirect(url_for('add_vehicle'))
        existing_vehicle = Vehicle.query.filter_by(vin=vin).first()
        if existing_vehicle:
            flash('A vehicle with this VIN already exists', 'danger')
            return redirect(url_for('add_vehicle'))
        try:
            vehicle = Vehicle(
                vin=vin,
                mileage=int(mileage),
                fuel_type=fuel_type,
                purchase_date=datetime.strptime(purchase_date, '%Y-%m-%d').date(),
                is_active=True
            )
            db.session.add(vehicle)
            db.session.commit()
            if session['role'] == 'Admin':
                create_log(admin_id=session['user_id'], action=f"Added vehicle with VIN {vin}", table_name="vehicles", record_id=vehicle.vehicle_id)
            flash('Vehicle added successfully', 'success')
            return redirect(url_for('vehicles'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {str(e)}', 'danger')
            return redirect(url_for('add_vehicle'))
    return render_template('add_vehicle.html')

@app.route('/vehicles/edit/<int:vehicle_id>', methods=['GET', 'POST'])
@login_required
def edit_vehicle(vehicle_id):
    vehicle = Vehicle.query.get_or_404(vehicle_id)
    if request.method == 'POST':
        vin = request.form.get('vin')
        mileage = request.form.get('mileage')
        fuel_type = request.form.get('fuel_type')
        purchase_date = request.form.get('purchase_date')
        is_active = True if request.form.get('is_active') else False
        if not all([vin, mileage, fuel_type, purchase_date]):
            flash('All fields are required', 'danger')
            return redirect(url_for('edit_vehicle', vehicle_id=vehicle_id))
        existing_vehicle = Vehicle.query.filter(Vehicle.vin == vin, Vehicle.vehicle_id != vehicle_id).first()
        if existing_vehicle:
            flash('Another vehicle with this VIN already exists', 'danger')
            return redirect(url_for('edit_vehicle', vehicle_id=vehicle_id))
        try:
            vehicle.vin = vin
            vehicle.mileage = int(mileage)
            vehicle.fuel_type = fuel_type
            vehicle.purchase_date = datetime.strptime(purchase_date, '%Y-%m-%d').date()
            vehicle.is_active = is_active
            db.session.commit()
            if session['role'] == 'Admin':
                create_log(admin_id=session['user_id'], action=f"Updated vehicle with VIN {vin}", table_name="vehicles", record_id=vehicle.vehicle_id)
            flash('Vehicle updated successfully', 'success')
            return redirect(url_for('vehicles'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {str(e)}', 'danger')
            return redirect(url_for('edit_vehicle', vehicle_id=vehicle_id))
    return render_template('edit_vehicle.html', vehicle=vehicle)

@app.route('/vehicles/deactivate/<int:vehicle_id>')
@login_required
def deactivate_vehicle(vehicle_id):
    vehicle = Vehicle.query.get_or_404(vehicle_id)
    try:
        vehicle.is_active = False
        db.session.commit()
        if session['role'] == 'Admin':
            create_log(admin_id=session['user_id'], action=f"Deactivated vehicle with VIN {vehicle.vin}", table_name="vehicles", record_id=vehicle.vehicle_id)
        flash('Vehicle deactivated successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred: {str(e)}', 'danger')
    return redirect(url_for('vehicles'))

@app.route('/reports')
@admin_required
def reports():
    reports_list = Report.query.order_by(Report.generated_at.desc()).all()
    return render_template('reports.html', reports=reports_list)

@app.route('/reports/generate', methods=['GET', 'POST'])
@admin_required
def generate_report():
    if request.method == 'POST':
        report_type = request.form.get('report_type')
        start_date = request.form.get('start_date')
        end_date = request.form.get('end_date')
        if not all([report_type, start_date, end_date]):
            flash('All fields are required', 'danger')
            return redirect(url_for('generate_report'))
        try:
            start = datetime.strptime(start_date, '%Y-%m-%d')
            end = datetime.strptime(end_date, '%Y-%m-%d')
            report_filename = f"report_{report_type.lower()}_{start.strftime('%Y%m%d')}_{end.strftime('%Y%m%d')}.xlsx"
            report_path = os.path.join('static', 'reports', report_filename)
            os.makedirs(os.path.join('static', 'reports'), exist_ok=True)
            fuel_data = db.session.query(FuelUsage, Vehicle.vin).join(
                Vehicle, FuelUsage.vehicle_id == Vehicle.vehicle_id
            ).filter(FuelUsage.fuel_date.between(start, end)).all()
            maintenance_data = db.session.query(Maintenance, Vehicle.vin).join(
                Vehicle, Maintenance.vehicle_id == Vehicle.vehicle_id
            ).filter(Maintenance.service_date.between(start, end)).all()
            fuel_df = pd.DataFrame([
                {'Vehicle VIN': item[1], 'Fuel Quantity': item[0].fuel_quantity, 'Fuel Cost': item[0].fuel_cost, 'Mileage': item[0].mileage_at_refuel, 'Date': item[0].fuel_date}
                for item in fuel_data
            ])
            maintenance_df = pd.DataFrame([
                {'Vehicle VIN': item[1], 'Service Type': item[0].service_type, 'Service Cost': item[0].service_cost, 'Date': item[0].service_date, 'Comments': item[0].comments}
                for item in maintenance_data
            ])
            with pd.ExcelWriter(report_path) as writer:
                fuel_df.to_excel(writer, sheet_name='Fuel Data', index=False)
                maintenance_df.to_excel(writer, sheet_name='Maintenance Data', index=False)
                if not fuel_df.empty and not maintenance_df.empty:
                    fuel_summary = fuel_df.groupby('Vehicle VIN').agg({'Fuel Quantity': 'sum', 'Fuel Cost': 'sum', 'Mileage': ['min', 'max']}).reset_index()
                    maintenance_summary = maintenance_df.groupby('Vehicle VIN').agg({'Service Cost': 'sum'}).reset_index()
                    summary = pd.merge(fuel_summary, maintenance_summary, on='Vehicle VIN', how='outer')
                    summary.to_excel(writer, sheet_name='Summary', index=False)
            report = Report(report_type=report_type, generated_by=session['user_id'], report_file_path=report_path)
            db.session.add(report)
            db.session.commit()
            create_log(admin_id=session['user_id'], action=f"Generated {report_type} report from {start_date} to {end_date}", table_name="reports", record_id=report.report_id)
            flash('Report generated successfully', 'success')
            return redirect(url_for('reports'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {str(e)}', 'danger')
            return redirect(url_for('generate_report'))
    return render_template('generate_report.html')

@app.route('/users')
@admin_required
def users():
    users_list = User.query.all()
    return render_template('users.html', users=users_list)

@app.route('/users/add', methods=['GET', 'POST'])
@admin_required
def add_user():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        if not all([username, email, password, role]):
            flash('All fields are required', 'danger')
            return redirect(url_for('add_user'))
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('add_user'))
        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'danger')
            return redirect(url_for('add_user'))
        try:
            user = User(username=username, email=email, password_hash=generate_password_hash(password), role=role, is_active=True)
            db.session.add(user)
            db.session.commit()
            create_log(admin_id=session['user_id'], action=f"Added user with username {username}", table_name="users", record_id=user.user_id)
            flash('User added successfully', 'success')
            return redirect(url_for('users'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {str(e)}', 'danger')
            return redirect(url_for('add_user'))
    return render_template('add_user.html')

@app.route('/users/edit/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        role = request.form.get('role')
        is_active = True if request.form.get('is_active') else False
        if not all([username, email, role]):
            flash('All fields are required', 'danger')
            return redirect(url_for('edit_user', user_id=user_id))
        if User.query.filter(User.username == username, User.user_id != user_id).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('edit_user', user_id=user_id))
        if User.query.filter(User.email == email, User.user_id != user_id).first():
            flash('Email already exists', 'danger')
            return redirect(url_for('edit_user', user_id=user_id))
        try:
            user.username = username
            user.email = email
            user.role = role
            user.is_active = is_active
            if password := request.form.get('password'):
                user.password_hash = generate_password_hash(password)
            db.session.commit()
            create_log(admin_id=session['user_id'], action=f"Updated user with username {username}", table_name="users", record_id=user.user_id)
            flash('User updated successfully', 'success')
            return redirect(url_for('users'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {str(e)}', 'danger')
            return redirect(url_for('edit_user', user_id=user_id))
    return render_template('edit_user.html', user=user)

@app.route('/analytics')
@login_required
def analytics():
    # Fuel usage by vehicle (for chart and summary)
    fuel_by_vehicle = db.session.query(
        Vehicle.vin,
        db.func.coalesce(db.func.sum(FuelUsage.fuel_quantity), 0).label('total_fuel')
    ).outerjoin(
        FuelUsage, Vehicle.vehicle_id == FuelUsage.vehicle_id
    ).group_by(
        Vehicle.vin
    ).all()
    print("Fuel by vehicle:", fuel_by_vehicle)

    # Maintenance costs by vehicle (for chart and summary)
    maintenance_by_vehicle = db.session.query(
        Vehicle.vin,
        db.func.coalesce(db.func.sum(Maintenance.service_cost), 0).label('total_cost')
    ).outerjoin(
        Maintenance, Vehicle.vehicle_id == Maintenance.vehicle_id
    ).group_by(
        Vehicle.vin
    ).all()
    print("Maintenance by vehicle:", maintenance_by_vehicle)

    # Generate charts
    def generate_chart(data, title, ylabel, filename):
        data = [(vin, total) for vin, total in data if total > 0]  # Only include non-zero totals for the chart
        print(f"Filtered data for {title}:", data)
        if not data:
            return None
        plt.figure(figsize=(10, 6))
        plt.bar([item[0] for item in data], [item[1] for item in data])
        plt.title(title)
        plt.xlabel('Vehicle VIN')
        plt.ylabel(ylabel)
        plt.xticks(rotation=45)
        plt.tight_layout()
        img = BytesIO()
        plt.savefig(img, format='png')
        img.seek(0)
        plot_url = base64.b64encode(img.getvalue()).decode('utf8')
        plt.close()
        return plot_url

    fuel_chart = generate_chart(fuel_by_vehicle, 'Fuel Usage by Vehicle', 'Total Fuel Quantity (gallons)', 'fuel_usage.png')
    maintenance_chart = generate_chart(maintenance_by_vehicle, 'Maintenance Costs by Vehicle', 'Total Cost ($)', 'maintenance_cost.png')

    # Prepare data for summary tables (include all vehicles, even with zero totals)
    fuel_data = [(vin, total) for vin, total in fuel_by_vehicle]
    maintenance_data = [(vin, total) for vin, total in maintenance_by_vehicle]

    return render_template(
        'analytics.html',
        fuel_chart=fuel_chart,
        maintenance_chart=maintenance_chart,
        fuel_data=fuel_data,
        maintenance_data=maintenance_data
    )
if __name__ == '__main__':
>>>>>>> master
    app.run(debug=True)