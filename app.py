from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from requests.auth import HTTPBasicAuth
from datetime import datetime, timedelta
import secrets
import base64
import os
import time
from random import random
from dotenv import load_dotenv


# Initialize Flask app
app = Flask(__name__)
load_dotenv()
app.secret_key = secrets.token_hex(16)

# Configure session
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)

# Configure database
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'carwash.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    bookings = db.relationship('Booking', backref='user', lazy=True)

class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    service_type = db.Column(db.String(50), nullable=False)
    booking_time = db.Column(db.DateTime, nullable=False)
    car_details = db.Column(db.String(200))
    carpet_area = db.Column(db.Integer)
    location = db.Column(db.String(100))
    phone = db.Column(db.Integer)
    total_amount = db.Column(db.Float, nullable=False)
    amount_paid = db.Column(db.Float, default=0.0)  # New column
    payment_status = db.Column(db.String(20), default='Pending')
    mpesa_receipt = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_completed = db.Column(db.Boolean, default=False)  # New column

# Admin credentials
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD') 
ADMIN_EMAIL = os.getenv('ADMIN_EMAIL')
ADMIN_PHONE = os.getenv('ADMIN_PHONE')

def initialize_database():
    with app.app_context():
        db.create_all()
        
        if not User.query.filter_by(username=ADMIN_USERNAME).first():
            admin = User(
                username=ADMIN_USERNAME,
                email=ADMIN_EMAIL,
                phone=ADMIN_PHONE,
                password=generate_password_hash(ADMIN_PASSWORD, method='pbkdf2:sha256'),
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
            print("Admin user created successfully")

initialize_database()

# M-Pesa Configuration
MPESA_CONSUMER_KEY = os.getenv('MPESA_CONSUMER_KEY')
MPESA_CONSUMER_SECRET = os.getenv('MPESA_CONSUMER_SECRET')
MPESA_PASSKEY = os.getenv('MPESA_PASSKEY')
MPESA_SHORTCODE =os.getenv('MPESA_SHORTCODE')
MPESA_CALLBACK_URL = os.getenv('MPESA_CALLBACK_URL') 
# Service Prices
SERVICE_PRICES = {
    'exterior': 1500,
    'interior': 10,
    'engine': 1000,
    'tire_rim': 800,
    'detailing': 2500,
    'carpet': 20  
}

def get_access_token():
    auth_url = 'https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials'
    response = requests.get(auth_url, auth=(MPESA_CONSUMER_KEY, MPESA_CONSUMER_SECRET))
    return response.json().get('access_token')

def initiate_stk_push(phone, amount, booking_id):
    if phone.startswith('0'):
        phone = '254' + phone[1:]
    elif phone.startswith('+254'):
        phone = phone.replace('+254', '254')
    
    access_token = get_access_token()
    api_url = 'https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest'
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    password = base64.b64encode((MPESA_SHORTCODE + MPESA_PASSKEY + timestamp).encode()).decode()
    
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    
    payload = {
        "BusinessShortCode": MPESA_SHORTCODE,
        "Password": password,
        "Timestamp": timestamp,
        "TransactionType": "CustomerPayBillOnline",
        "Amount": amount,
        "PartyA": phone,
        "PartyB": MPESA_SHORTCODE,
        "PhoneNumber": phone,
        "CallBackURL": MPESA_CALLBACK_URL,
        "AccountReference": f"CarWash{booking_id}",
        "TransactionDesc": "Car Wash Service"
    }
    
    response = requests.post(api_url, json=payload, headers=headers)
    return response.json()

# Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        phone = request.form.get('phone', '').strip()
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        
        if not all([username, email, phone, password, confirm_password]):
            flash('All fields are required!', 'danger')
            return redirect(url_for('register'))
        
        if len(username) < 4 or len(username) > 20:
            flash('Username must be between 4-20 characters', 'danger')
            return redirect(url_for('register'))
            
        if len(password) < 6:
            flash('Password must be at least 6 characters', 'danger')
            return redirect(url_for('register'))
            
        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('register'))
        
        try:
            if User.query.filter_by(username=username).first():
                flash('Username already taken. Please choose another.', 'danger')
                return redirect(url_for('register'))
                
            if User.query.filter_by(email=email).first():
                flash('Email already registered. Please use another email.', 'danger')
                return redirect(url_for('register'))
                
            if User.query.filter_by(phone=phone).first():
                flash('Phone number already registered.', 'danger')
                return redirect(url_for('register'))
                
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            new_user = User(
                username=username,
                email=email,
                phone=phone,
                password=hashed_password,
                is_admin=False
            )
            
            db.session.add(new_user)
            db.session.commit()
            
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Registration error: {str(e)}')
            flash('An error occurred during registration. Please try again.', 'danger')
            return redirect(url_for('register'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not username or not password:
            flash('Please enter both username and password', 'danger')
            return redirect(url_for('login'))
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            flash('Login successful!', 'success')
            
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('dashboard'))
        
        flash('Invalid username or password!', 'danger')
        return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/services')
def services():
    if 'user_id' not in session:
        flash('Please login to access services.', 'warning')
        return redirect(url_for('login'))
    return render_template('services.html', services=SERVICE_PRICES)

@app.route('/book/<service_type>', methods=['GET', 'POST'])
def book_service(service_type):
    if 'user_id' not in session:
        flash('Please login to book a service.', 'warning')
        return redirect(url_for('login'))
    
    if service_type not in SERVICE_PRICES:
        flash('Invalid service selected.', 'danger')
        return redirect(url_for('services'))
    
    if request.method == 'POST':
        try:
            booking_time = request.form.get('booking_time')
            car_details = request.form.get('car_details', '').strip()
            carpet_area = int(request.form.get('carpet_area', 0))
            phone = request.form.get('phone', '').strip()
            location = request.form.get('location', '').strip()
            
            if not booking_time or not car_details:
                flash('Please fill all required fields', 'danger')
                return redirect(url_for('book_service', service_type=service_type))
            
            if service_type == 'carpet' and carpet_area <= 0:
                flash('Please enter a valid carpet area', 'danger')
                return redirect(url_for('book_service', service_type=service_type))
            
            base_amount = SERVICE_PRICES[service_type]
            total_amount = base_amount * carpet_area if service_type == 'carpet' else base_amount
            
            new_booking = Booking(
                user_id=session['user_id'],
                service_type=service_type,
                booking_time=datetime.strptime(booking_time, '%Y-%m-%dT%H:%M'),
                car_details=car_details,
                carpet_area=carpet_area if service_type == 'carpet' else None,
                total_amount=total_amount,
                phone = phone,
                location = location
            )
            
            db.session.add(new_booking)
            db.session.commit()
            
            session['current_booking'] = new_booking.id
            return redirect(url_for('payment'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Booking error: {str(e)}')
            flash('An error occurred during booking. Please try again.', 'danger')
            return redirect(url_for('book_service', service_type=service_type))
    
    return render_template('booking.html', service_type=service_type, service_price=SERVICE_PRICES[service_type])

@app.route('/payment', methods=['GET', 'POST'])
def payment():
    if 'user_id' not in session or 'current_booking' not in session:
        flash('Invalid payment request.', 'danger')
        return redirect(url_for('services'))
    
    booking = Booking.query.get(session['current_booking'])
    user = User.query.get(session['user_id'])
    
    if not booking or booking.user_id != user.id:
        flash('Invalid booking reference.', 'danger')
        return redirect(url_for('services'))
    
    if request.method == 'POST':
        try:
            payment_type = request.form.get('payment_type')  # 'deposit' or 'full'
            amount = float(request.form.get('amount', booking.total_amount))
            
            if payment_type == 'deposit':
                min_deposit = booking.total_amount * 0.2
                if amount < min_deposit:
                    flash(f'Deposit must be at least KSH {min_deposit:.2f}', 'danger')
                    return redirect(url_for('payment'))
                
                response = initiate_stk_push(user.phone, amount, booking.id)
                
                if response.get('ResponseCode') == '0':
                    booking.amount_paid = amount
                    booking.payment_status = 'Partial'
                    booking.mpesa_receipt = response.get('CheckoutRequestID')
                    db.session.commit()
                    flash(f'Deposit of KSH {amount:.2f} payment initiated. Please complete the payment on your phone.', 'success')
                    return redirect(url_for('dashboard'))
            
            elif payment_type == 'full':
                remaining_amount = booking.total_amount - booking.amount_paid
                if amount < remaining_amount:
                    flash(f'Please pay at least KSH {remaining_amount:.2f} to complete payment', 'danger')
                    return redirect(url_for('payment'))
                
                response = initiate_stk_push(user.phone, amount, booking.id)
                
                if response.get('ResponseCode') == '0':
                    booking.amount_paid += amount
                    booking.payment_status = 'Completed' if booking.amount_paid >= booking.total_amount else 'Partial'
                    booking.mpesa_receipt = response.get('CheckoutRequestID')
                    db.session.commit()
                    flash('Payment initiated. Please complete the payment on your phone.', 'success')
                    return redirect(url_for('dashboard'))
            
            else:
                error_message = response.get('errorMessage', 'Payment initiation failed')
                flash(f'Payment error: {error_message}', 'danger')
                return redirect(url_for('payment'))
                
        except Exception as e:
            app.logger.error(f'Payment error: {str(e)}')
            flash('Payment processing failed. Please try again.', 'danger')
            return redirect(url_for('payment'))
    
    remaining_balance = booking.total_amount - booking.amount_paid
    return render_template('payment.html', 
                         booking=booking, 
                         user=user,
                         remaining_balance=remaining_balance)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please login to view dashboard.', 'warning')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    bookings = Booking.query.filter_by(user_id=user.id).order_by(Booking.booking_time.desc()).all()
    
    return render_template('dashboard.html', 
                         user=user, 
                         bookings=bookings,
                         now=datetime.utcnow())

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'user_id' not in session:
        flash('Please login to access admin dashboard.', 'warning')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if not user.is_admin:
        flash('You are not authorized to access this page.', 'danger')
        return redirect(url_for('dashboard'))
    
    bookings = db.session.query(Booking, User).join(User).order_by(Booking.booking_time.desc()).all()
    users = User.query.all()
    
    return render_template('admin_dashboard.html', 
                         bookings=bookings, 
                         users=users,
                         services=SERVICE_PRICES)

@app.route('/admin/delete_booking/<int:booking_id>', methods=['POST'])
def admin_delete_booking(booking_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    user = User.query.get(session['user_id'])
    if not user.is_admin:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    booking = Booking.query.get(booking_id)
    if not booking:
        return jsonify({'success': False, 'message': 'Booking not found'}), 404
    
    try:
        db.session.delete(booking)
        db.session.commit()
        return jsonify({
            'success': True, 
            'message': 'Booking deleted successfully',
            'booking_id': booking_id
        })
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting booking: {str(e)}")
        return jsonify({
            'success': False, 
            'message': f'Error deleting booking: {str(e)}'
        }), 500

@app.route('/admin/complete_booking/<int:booking_id>', methods=['POST'])
def admin_complete_booking(booking_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    user = User.query.get(session['user_id'])
    if not user.is_admin:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    booking = Booking.query.get(booking_id)
    if not booking:
        return jsonify({'success': False, 'message': 'Booking not found'}), 404
    
    try:
        booking.is_completed = True
        db.session.commit()
        return jsonify({
            'success': True, 
            'message': 'Booking marked as completed',
            'booking_id': booking_id
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False, 
            'message': f'Error: {str(e)}'
        }), 500

@app.route('/callback', methods=['POST'])
def callback():
    try:
        data = request.get_json()
        print("Raw callback data:", data)
        
        result_code = data.get('Body', {}).get('stkCallback', {}).get('ResultCode')
        checkout_request_id = data.get('Body', {}).get('stkCallback', {}).get('CheckoutRequestID')
        mpesa_receipt = data.get('Body', {}).get('stkCallback', {}).get('CallbackMetadata', {}).get('Item', [{}])[1].get('Value')

        if result_code == '0':
            booking = Booking.query.filter_by(mpesa_receipt=checkout_request_id).first()
            if booking:
                booking.payment_status = 'Completed'
                booking.mpesa_receipt = mpesa_receipt
                db.session.commit()
                print(f"Updated booking {booking.id} to Completed")
        
        return jsonify({"ResultCode": 0, "ResultDesc": "Success"}), 200

    except Exception as e:
        print("Callback processing error:", str(e))
        return jsonify({"ResultCode": 1, "ResultDesc": "Error"}), 500

@app.route('/check_payment/<int:booking_id>')
def check_payment(booking_id):
    if 'user_id' not in session:
        flash('Please login', 'warning')
        return redirect(url_for('login'))
    
    booking = Booking.query.get(booking_id)
    if not booking:
        flash('Booking not found', 'danger')
        return redirect(url_for('dashboard'))
    
    if booking.user_id != session['user_id'] and not session.get('is_admin'):
        flash('Unauthorized', 'danger')
        return redirect(url_for('dashboard'))
    
    if booking.payment_status == 'Pending':
        if random() > 0.5:  # 50% chance to "find" a payment
            booking.payment_status = 'Completed'
            db.session.commit()
            flash('Payment confirmed!', 'success')
        else:
            flash('Payment still pending', 'info')
    else:
        flash('Payment already completed', 'info')
    
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)