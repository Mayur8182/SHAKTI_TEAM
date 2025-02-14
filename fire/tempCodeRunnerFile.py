from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_mail import Mail, Message
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, SubmitField
from wtforms.validators import InputRequired, EqualTo, Email
from flask_wtf.csrf import CSRFProtect
import bcrypt
from pymongo import MongoClient
from PIL import Image
import pytesseract
import re
import os
import time
import secrets
from datetime import datetime, timedelta
from bson import ObjectId
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO, emit

# Initialize Flask App
app = Flask(__name__)
socketio = SocketIO(app)
app.secret_key = 'your_secret_key'  # Change this to a secure secret key
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['UPLOAD_FOLDER'] = 'uploads'

# CSRF protection
csrf = CSRFProtect(app)

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'  # Update with your email
app.config['MAIL_PASSWORD'] = 'your_app_password'  # Update with your app password
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

mail = Mail(app)

# MongoDB connection
client = MongoClient('mongodb://localhost:27017/')
db = client['aek_noc']
users = db['users']
applications = db['applications']
contacts = db['contacts']
activities = db['activities']  # New collection for activity logging

# Tesseract configuration
pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

# Utility Functions
def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def detect_document_content(image_path):
    try:
        img = Image.open(image_path)
        extracted_text = pytesseract.image_to_string(img)

        aadhar_pattern = r'\d{4} \d{4} \d{4}'
        pan_pattern = r'[A-Z]{5}[0-9]{4}[A-Z]{1}'

        aadhar_match = re.search(aadhar_pattern, extracted_text)
        pan_match = re.search(pan_pattern, extracted_text)

        errors = []
        if not aadhar_match:
            errors.append("Aadhar number not found or invalid format.")
        if not pan_match:
            errors.append("PAN number not found or invalid format.")

        return extracted_text, errors
    except Exception as e:
        return "", [str(e)]

def send_email(subject, recipient, body):
    try:
        msg = Message(subject, sender=app.config['MAIL_USERNAME'], recipients=[recipient])
        msg.body = body
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

def log_activity(activity_type, description, username=None):
    try:
        activities.insert_one({
            'type': activity_type,
            'description': description,
            'username': username or session.get('username'),
            'timestamp': datetime.now()
        })
    except Exception as e:
        print(f"Error logging activity: {e}")

# Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    name = StringField('Full Name', validators=[InputRequired()])
    email = StringField('Email Address', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired()])
    confirm_password = PasswordField('Confirm Password', 
                                   validators=[InputRequired(), EqualTo('password')])
    role = SelectField('Register As', 
                      choices=[('admin', 'Admin'), ('manager', 'Manager'), 
                              ('inspector', 'Inspector')])
    submit = SubmitField('Register')

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data.encode('utf-8')

        user = users.find_one({'username': username})
        if user and bcrypt.checkpw(password, user['password']):
            session['username'] = username
            session['role'] = user.get('role', 'user')
            session['email'] = user.get('email')
            session.permanent = True
            
            log_activity('Login', f"User {username} logged in")
            
            if session['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('user_dashboard'))
            
        flash('Invalid username or password', 'danger')
    
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        if users.find_one({'username': form.username.data}):
            flash('Username already exists!', 'danger')
        else:
            hashed_password = bcrypt.hashpw(
                form.password.data.encode('utf-8'), 
                bcrypt.gensalt()
            )
            user_data = {
                'username': form.username.data,
                'name': form.name.data,
                'email': form.email.data,
                'password': hashed_password,
                'role': form.role.data,
                'created_at': datetime.now()
            }
            users.insert_one(user_data)
            
            log_activity('Registration', f"New user registered: {form.username.data}")
            send_email(
                'Welcome to AEK NOC System',
                form.email.data,
                'Thank you for registering with AEK NOC System.'
            )
            
            flash('Registration successful!', 'success')
            return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

@app.route('/admin_dashboard')
def admin_dashboard():
    if session.get('role') != 'admin':
        flash('Access denied!', 'danger')
        return redirect(url_for('login'))
    
    return render_template('admin_dashboard.html')

@app.route('/user_dashboard')
def user_dashboard():
    if 'username' not in session:
        flash('Please log in first!', 'danger')
        return redirect(url_for('login'))
    
    user_applications = applications.find({'username': session['username']})
    return render_template('user_dashboard.html', applications=user_applications)

@app.route('/submit_noc', methods=['POST'])
def submit_noc():
    if 'username' not in session:
        return jsonify({'error': 'Please log in first'}), 401

    try:
        # Collect form data
        application_data = {
            'username': session['username'],
            'business_name': request.form.get('businessName'),
            'business_type': request.form.get('businessType'),
            'business_address': request.form.get('businessAddress'),
            'contact_number': request.form.get('contactNumber'),
            'fire_extinguishers': request.form.get('fireExtinguishers'),
            'fire_alarm': request.form.get('fireAlarm'),
            'emergency_exits': request.form.get('emergencyExits'),
            'last_fire_drill': request.form.get('lastFireDrill'),
            'status': 'pending',
            'timestamp': datetime.now(),
            'email': session.get('email', '')
        }

        # Handle file uploads
        files = {}
        for file_key in ['buildingPlan', 'safetyCertificate', 'insuranceDoc']:
            if file_key in request.files:
                file = request.files[file_key]
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)
                    files[file_key] = filename

        application_data['files'] = files
        result = applications.insert_one(application_data)
        
        # Log activity and send notifications
        log_activity(
            'Application Submitted',
            f"New NOC application submitted for: {application_data['business_name']}"
        )
        
        # Notify admin
        admin_notification = f'''New NOC application received:
Business Name: {application_data['business_name']}
Business Type: {application_data['business_type']}
Application ID: {str(result.inserted_id)}'''
        
        send_email(
            'New NOC Application Submitted',
            app.config['mkbharvadbharvad534@gmail.com'],  # Admin mkemail
            admin_notification
        )

        # Emit socket.io event
        socketio.emit('new_application', {
            'message': 'New application submitted!',
            'applicationId': str(result.inserted_id)
        })

        return jsonify({
            'success': True,
            'message': 'NOC application submitted successfully!',
            'application_id': str(result.inserted_id)
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/dashboard-stats')
def get_dashboard_stats():
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        stats = {
            'total': applications.count_documents({}),
            'pending': applications.count_documents({'status': 'pending'}),
            'approved': applications.count_documents({'status': 'approved'}),
            'rejected': applications.count_documents({'status': 'rejected'})
        }
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/recent-activities')
def get_recent_activities():
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        recent = list(activities.find(
            {},
            {'_id': 0}
        ).sort('timestamp', -1).limit(10))
        
        # Convert timestamps to ISO format
        for activity in recent:
            activity['timestamp'] = activity['timestamp'].isoformat()
            
        return jsonify({'activities': recent})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/latest-applications')
def get_latest_applications():
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        latest = list(applications.find(
            {},
            {
                '_id': 1,
                'business_name': 1,
                'status': 1,
                'timestamp': 1
            }
        ).sort('timestamp', -1).limit(5))

        # Convert ObjectId to string
        for app in latest:
            app['id'] = str(app['_id'])
            del app['_id']

        return jsonify({'applications': latest})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
# Application Routes
@app.route('/application/<application_id>', methods=['GET'])
def get_application_details(application_id):
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        application = applications.find_one({'_id': ObjectId(application_id)})
        if not application:
            return jsonify({'error': 'Application not found'}), 404

        if session.get('role') != 'admin' and application['username'] != session['username']:
            return jsonify({'error': 'Unauthorized'}), 401

        formatted_application = {
            'id': str(application['_id']),
            'business_name': application.get('business_name', ''),
            'business_type': application.get('business_type', ''),
            'business_address': application.get('business_address', ''),
            'contact_number': application.get('contact_number', ''),
            'username': application.get('username', ''),
            'email': application.get('email', ''),
            'status': application.get('status', 'pending'),
            'timestamp': application['timestamp'].isoformat() if 'timestamp' in application else '',
            'last_updated': application.get('updated_at', datetime.now()).isoformat(),
            'updated_by': application.get('updated_by', ''),
            'fire_safety': {
                'fire_extinguishers': application.get('fire_extinguishers', ''),
                'fire_alarm': application.get('fire_alarm', ''),
                'emergency_exits': application.get('emergency_exits', ''),
                'last_fire_drill': application.get('last_fire_drill', '')
            },
            'files': []
        }

        if 'files' in application:
            for file_type, filename in application['files'].items():
                formatted_application['files'].append({
                    'type': file_type,
                    'filename': filename,
                    'url': url_for('download_file', filename=filename, _external=True)
                })

        return jsonify(formatted_application)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/application/<application_id>/approve', methods=['POST'])
def approve_application(application_id):
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        # Update application status to approved
        update_result = applications.update_one(
            {'_id': ObjectId(application_id)},
            {
                '$set': {
                    'status': 'approved',
                    'updated_at': datetime.now(),
                    'updated_by': session['username'],
                    'approval_date': datetime.now(),
                    'approved_by': session['username']
                }
            }
        )

        if update_result.modified_count == 0:
            return jsonify({'error': 'Application not found'}), 404

        # Get updated application details
        application = applications.find_one({'_id': ObjectId(application_id)})
        
        # Log activity
        log_activity(
            'Application Approved',
            f"Application {application_id} approved by {session['username']}"
        )
        
        # Send email notification
        if application.get('email'):
            email_body = f"""
            Your NOC application has been APPROVED.
            
            Application Details:
            - Application ID: {application_id}
            - Business Name: {application.get('business_name', 'N/A')}
            - Approved By: {session['username']}
            - Approval Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            
            Please log in to your account to download your NOC certificate.
            """
            
            send_email(
                'NOC Application Approved',
                application['email'],
                email_body
            )

        # Emit socket.io event
        socketio.emit('application_approved', {
            'applicationId': str(application_id),
            'status': 'approved',
            'updatedAt': datetime.now().isoformat(),
            'updatedBy': session['username']
        })

        return jsonify({
            'success': True,
            'message': 'Application approved successfully',
            'application': {
                'id': str(application['_id']),
                'status': 'approved',
                'updated_at': datetime.now().isoformat(),
                'updated_by': session['username']
            }
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/application/<application_id>/reject', methods=['POST'])
def reject_application(application_id):
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        # Get rejection reason from request
        rejection_reason = request.json.get('reason', 'No reason provided')

        # Update application status to rejected
        update_result = applications.update_one(
            {'_id': ObjectId(application_id)},
            {
                '$set': {
                    'status': 'rejected',
                    'updated_at': datetime.now(),
                    'updated_by': session['username'],
                    'rejection_date': datetime.now(),
                    'rejected_by': session['username'],
                    'rejection_reason': rejection_reason
                }
            }
        )

        if update_result.modified_count == 0:
            return jsonify({'error': 'Application not found'}), 404

        # Get updated application details
        application = applications.find_one({'_id': ObjectId(application_id)})
        
        # Log activity
        log_activity(
            'Application Rejected',
            f"Application {application_id} rejected by {session['username']}. Reason: {rejection_reason}"
        )
        
        # Send email notification
        if application.get('email'):
            email_body = f"""
            Your NOC application has been REJECTED.
            
            Application Details:
            - Application ID: {application_id}
            - Business Name: {application.get('business_name', 'N/A')}
            - Rejected By: {session['username']}
            - Rejection Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            - Reason: {rejection_reason}
            
            Please log in to your account for more details or to submit a revised application.
            """
            
            send_email(
                'NOC Application Rejected',
                application['email'],
                email_body
            )

        # Emit socket.io event
        socketio.emit('application_rejected', {
            'applicationId': str(application_id),
            'status': 'rejected',
            'updatedAt': datetime.now().isoformat(),
            'updatedBy': session['username'],
            'reason': rejection_reason
        })

        return jsonify({
            'success': True,
            'message': 'Application rejected successfully',
            'application': {
                'id': str(application['_id']),
                'status': 'rejected',
                'updated_at': datetime.now().isoformat(),
                'updated_by': session['username'],
                'rejection_reason': rejection_reason
            }
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/application/<application_id>/update-status', methods=['POST'])
def update_application_status(application_id):
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        status = request.json.get('status')
        if status not in ['pending', 'approved', 'rejected']:
            return jsonify({'error': 'Invalid status'}), 400

        if status == 'approved':
            return approve_application(application_id)
        elif status == 'rejected':
            return reject_application(application_id)
        
        # Handle pending status
        update_result = applications.update_one(
            {'_id': ObjectId(application_id)},
            {
                '$set': {
                    'status': status,
                    'updated_at': datetime.now(),
                    'updated_by': session['username']
                }
            }
        )

        if update_result.modified_count == 0:
            return jsonify({'error': 'Application not found'}), 404

        application = applications.find_one({'_id': ObjectId(application_id)})
        
        log_activity(
            'Status Update',
            f"Application {application_id} status changed to {status} by {session['username']}"
        )
        
        socketio.emit('application_updated', {
            'applicationId': str(application_id),
            'status': status,
            'updatedAt': datetime.now().isoformat(),
            'updatedBy': session['username']
        })

        return jsonify({
            'success': True,
            'message': f'Application status updated to {status}',
            'application': {
                'id': str(application['_id']),
                'status': status,
                'updated_at': datetime.now().isoformat(),
                'updated_by': session['username']
            }
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/download/<filename>')
def download_file(filename):
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    try:
        return send_from_directory(
            app.config['UPLOAD_FOLDER'],
            filename,
            as_attachment=True
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/logout')
def logout():
    if 'username' in session:
        log_activity('Logout', f"User {session['username']} logged out")
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/generate_csrf_token', methods=['GET'])
def generate_csrf_token():
    token = secrets.token_urlsafe(32)
    session['csrf_token'] = token
    return jsonify({'csrf_token': token})



@app.route('/submit_contact', methods=['POST'])
def submit_contact():
    try:
        contact_data = {
            'name': request.form.get('name'),
            'email': request.form.get('email'),
            'message': request.form.get('message'),
            'timestamp': datetime.now()
        }

        if not all([contact_data['name'], contact_data['email'], contact_data['message']]):
            return jsonify({'error': 'All fields are required'}), 400

        contacts.insert_one(contact_data)
        
        log_activity('Contact Form Submission', f"New contact form submission from {contact_data['email']}")

        return jsonify({'success': True, 'message': 'Message sent successfully!'})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/manage_applications')
def manage_applications():
    if session.get('role') != 'admin':
        flash('Access denied!', 'danger')
        return redirect(url_for('login'))

    applications_data = list(applications.find({}))
    for app in applications_data:
        app['_id'] = str(app['_id'])  # Convert ObjectId to string

    return render_template('manage_applications.html', applications=applications_data)

@app.route('/manage_users')
def manage_users():
    if session.get('role') != 'admin':
        flash('Access denied!', 'danger')
        return redirect(url_for('login'))

    users_data = list(users.find({}, {'password': 0})) # Exclude password
    return render_template('manage_users.html', users=users_data)

@app.route('/user/<user_id>/delete', methods=['POST'])
def delete_user(user_id):
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        result = users.delete_one({'_id': ObjectId(user_id)})
        if result.deleted_count == 0:
            return jsonify({'error': 'User not found'}), 404

        log_activity('User Deletion', f"User {user_id} deleted by {session['username']}")

        return jsonify({'success': True, 'message': 'User deleted successfully!'})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/application/<application_id>/delete', methods=['POST'])
def delete_application(application_id):
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        result = applications.delete_one({'_id': ObjectId(application_id)})
        if result.deleted_count == 0:
            return jsonify({'error': 'Application not found'}), 404

        log_activity('Application Deletion', f"Application {application_id} deleted by {session['username']}")

        return jsonify({'success': True, 'message': 'Application deleted successfully!'})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/user/<user_id>') #for fetching user details
def get_user_details(user_id):
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        user = users.find_one({'_id': ObjectId(user_id)}, {'password': 0}) #exclude password
        if not user:
            return jsonify({'error': 'User not found'}), 404

        user['_id'] = str(user['_id']) #convert object id to string
        return jsonify(user)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/user/<user_id>/update', methods=['POST'])
def update_user(user_id):
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        updated_data = request.get_json()  # Get the JSON data from the request body

        # Check if the username already exists (excluding the current user being updated)
        existing_user = users.find_one({'username': updated_data.get('username')})
        if existing_user and str(existing_user['_id']) != user_id:
            return jsonify({'error': 'Username already exists'}), 400

        result = users.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': updated_data}
        )

        if result.modified_count == 0:
            return jsonify({'error': 'User not found'}), 404

        log_activity('User Update', f"User {user_id} updated by {session['username']}")

        return jsonify({'success': True, 'message': 'User details updated successfully!'})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ... (rest of the code)

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    socketio.run(app, debug=True)