from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory, Response, send_file
from flask_mail import Mail, Message
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, SubmitField, FileField
from wtforms.validators import InputRequired, EqualTo, Email
from flask_wtf.csrf import CSRFProtect
import bcrypt
from pymongo import MongoClient
from PIL import Image, ImageDraw, ImageFont
import pytesseract
import re
import os
import time
import secrets
from datetime import datetime, timedelta
from bson import ObjectId
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO, emit
from bson.json_util import dumps, loads
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm, cm
from io import BytesIO
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
import csv
import qrcode
from flask import make_response
from io import StringIO
from io import BytesIO
import csv
from io import TextIOWrapper
from flask_cors import CORS
import pdfkit
from fire.utils.aadhaar_utils import extract_aadhaar, find_user_by_aadhaar
import string
import random

# Initialize Flask App
app = Flask(__name__, 
    template_folder='templates',ath(os.path.join(os.path.dirname(__file__), 'templates')),
    static_folder='static'abspath(os.path.join(os.path.dirname(__file__), 'static'))
)
CORS(app)  # Enable CORS for all routes
socketio = SocketIO(app, cors_allowed_origins="*")
socketio = SocketIO(app, cors_allowed_origins="*")
app.secret_key = 'your_secret_key'  # Change this to a secure secret key
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['UPLOAD_FOLDER'] = 'uploads'

# Add template directory config
app.template_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
app.static_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')

# CSRF protection
csrf = CSRFProtect(app)
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USE_SSL=False,
    MAIL_USERNAME='mkbharvad534@gmail.com',  # Your Gmail
    MAIL_PASSWORD='dwtp fmiq miyl ccvq',     # Your app password
    MAIL_DEFAULT_SENDER='mkbharvad534@gmail.com'
)

# Initialize Flask-Mail
mail = Mail(app)

def send_email(subject, recipient, body):
    try:
        msg = Message(subject, recipients=[recipient])
        msg.body = body
        mail.send(msg)
        log_activity('Email', f"Email sent successfully to {recipient}")
        return True
    except Exception as e:
        error_msg = f"Error sending email to {recipient}: {str(e)}"
        log_activity('Email Error', error_msg)
        print(error_msg)  # For immediate debugging
        return False

# MongoDB connection
mongo_uri = os.getenv('MONGODB_URI', 'mongodb+srv://mkbharvad8080:Mkb%408080@cluster0.a82h2.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0')
client = MongoClient(mongo_uri)
db = client.get_database('aek_noc')

# Initialize collections after database connection
users = db['users']
applications = db['applications']
contacts = db['contacts']
activities = db['activities']
reports = db['reports']
licenses = db['licenses']
inspections = db['inspections']
notifications = db['notifications']

# Create indexes only if they don't exist
def setup_indexes():
    try:
        # Create indexes for inspections collection
        inspections.create_index([('date', 1)], background=True)
        inspections.create_index([('status', 1)], background=True)
        inspections.create_index([('business_id', 1)], background=True)
        inspections.create_index([('inspector_id', 1)], background=True)
        
        # Create indexes for applications collection
        applications.create_index([('status', 1)], background=True)
        applications.create_index([('timestamp', -1)], background=True)
        applications.create_index([('business_name', 1)], background=True)
    except Exception as e:
        print(f"Error creating indexes: {str(e)}")

# Initialize indexes after app creation
setup_indexes()

# Tesseract configuration
if os.name == 'nt':  # Windows
    pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
else:  # Linux/Unix
    pytesseract.pytesseract.tesseract_cmd = '/usr/bin/tesseract'


# Add these configurations after app initialization
UPLOAD_FOLDER = 'static/profile_images'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Create upload folder if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Utility Functions
def detect_document_content(image_path):
    try:
        # Check if the file is a PDF
        if (image_path.lower().endswith('.pdf')):
            return "PDF document", []  # Skip content detection for PDFs
            
        # For images, perform OCR
        img = Image.open(image_path)
        extracted_text = pytesseract.image_to_string(img)

        # Define patterns to check
        patterns = {
            'address': r'\d+\s+[A-Za-z\s,]+',
            'phone': r'\d{10}',
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        }

        errors = []
        for key, pattern in patterns.items():
            if not re.search(pattern, extracted_text):
                errors.append(f"Could not detect {key}")

        return extracted_text, errors
    except Exception as e:
        return "", [str(e)]

def log_activity(activity_type, description, username=None):
    try:
        activity = {
            'timestamp': datetime.now(),
            'activity_type': activity_type,
            'description': description,
            'username': username or session.get('username', 'System')
        }
        activities.insert_one(activity)
    except Exception as e:
        print(f"Error logging activity: {str(e)}")

def send_registration_email(user_data):
    subject = "Welcome to AEK NOC System - Registration Successful"
    body = f"""
Dear {user_data['name']},

Thank you for registering with AEK NOC System. Your account has been successfully created.

Account Details:
- Username: {user_data['username']}
- Role: {user_data['role'].title()}
- Email: {user_data['email']}

You can now login at: {url_for('login', _external=True)}

For security reasons, please change your password after your first login.

If you have any questions, please don't hesitate to contact us.

Best regards,
AEK NOC System Team
"""
    send_email(subject, user_data['email'], body)

def send_application_confirmation_email(application_data, application_id):
    subject = "NOC Application Submitted Successfully"
    body = f"""
Dear {session.get('name', 'User')},

Your NOC application has been successfully submitted. Here are the details:

Application Details:
- Application ID: {str(application_id)}
- Business Name: {application_data['business_name']}
- Business Type: {application_data['business_type']}
- Submission Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Business Information:
- Address: {application_data['business_address']}
- Contact Number: {application_data['contact_number']}

Safety Measures:
- Fire Extinguishers: {application_data['fire_extinguishers']}
- Fire Alarm: {application_data['fire_alarm']}
- Emergency Exits: {application_data['emergency_exits']}
- Last Fire Drill: {application_data['last_fire_drill']}

You can check your application status at:
{url_for('view_application', application_id=str(application_id), _external=True)}

We will review your application and notify you of any updates.

Thank you for using our service.

Best regards,
AEK NOC System Team
"""
    send_email(subject, application_data['email'], body)

def send_approval_email_with_report(application, report_buffer):
    """Send approval email with attached NOC report"""
    try:
        subject = "NOC Application Approved - Certificate Attached"
        body = f"""
Dear {application.get('name', 'Applicant')},

Congratulations! Your NOC application has been APPROVED.

Application Details:
- Application ID: {str(application['_id'])}
- Business Name: {application.get('business_name')}
- Submission Date: {application.get('timestamp', datetime.now()).strftime('%Y-%m-%d %H:%M:%S')}
- Approved By: {session.get('username')}
- Approval Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- Valid Until: {(datetime.now() + timedelta(days=365)).strftime('%Y-%m-%d')}
- Business Information:
- Address: {application.get('business_address')}
- Contact Number: {application.get('contact_number')}

Safety Measures Verified:
- Fire Extinguishers: {application.get('fire_extinguishers', 'Verified')}
- Fire Alarm: {application.get('fire_alarm', 'Verified')}
- Emergency Exits: {application.get('emergency_exits', 'Verified')}
- Last Fire Drill: {application.get('last_fire_drill', 'Verified')}

Your NOC certificate is attached to this email. Please keep it for your records.
You can also view and download your certificate by logging into your dashboard:
{url_for('view_application', application_id=str(application['_id']), _external=True)}

Best regards,
AEK NOC System Team
"""
        # Create email message
        msg = Message(
            subject,
            sender=app.config['MAIL_USERNAME'],
            recipients=[application.get('email')]
        )
        msg.body = body

        # Attach the PDF report
        report_buffer.seek(0)
        msg.attach(
            f"NOC_Certificate_{application.get('business_name', 'Business')}.pdf",
            "application/pdf",
            report_buffer.read()
        )

        # Send email
        mail.send(msg)
        
        # Log the email sending
        log_activity(
            'Email Sent',
            f"Approval email sent to {application.get('email')} for application {str(application['_id'])}"
        )
        return True

    except Exception as e:
        print(f"Error sending approval email: {str(e)}")
        log_activity(
            'Email Error',
            f"Failed to send approval email: {str(e)}"
        )
        return False

def send_rejection_email(application, reason):
    """Send rejection email with reason"""
    try:
        subject = "NOC Application Rejected"
        body = f"""
Dear {application.get('name', 'Applicant')},

We regret to inform you that your NOC application has been REJECTED.

Application Details:
- Application ID: {str(application['_id'])}
- Business Name: {application.get('business_name')}
- Submission Date: {application.get('timestamp', datetime.now()).strftime('%Y-%m-%d %H:%M:%S')}
- Rejected By: {session.get('username')}
- Rejection Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Business Information:
- Address: {application.get('business_address')}
- Contact Number: {application.get('contact_number')}

Reason for Rejection:
{reason}

Required Actions:
1. Review the rejection reason carefully
2. Make necessary corrections and improvements
3. Submit a new application addressing the concerns

You can submit a new application after addressing the above concerns by logging into your dashboard:
{url_for('user_dashboard', _external=True)}

If you have any questions or need clarification, please don't hesitate to contact us.

Best regards,
AEK NOC System Team
"""
        # Create and send email
        msg = Message(
            subject,
            sender=app.config['MAIL_USERNAME'],
            recipients=[application.get('email')]
        )
        msg.body = body
        mail.send(msg)
        email_sent = True
    except Exception as e:
        print(f"Error sending rejection email: {str(e)}")
        email_sent = False

    # Log activity
    log_activity(
        'Application Rejection',
        f"Application {application['_id']} rejected and {'email sent' if email_sent else 'email failed'}"
    )
    
    # Emit socket event
    socketio.emit('application_status_changed', {
        'application_id': str(application['_id']),
        'status': 'rejected',
        'message': 'Application has been rejected!'
    })
    
    return jsonify({
        'success': True, 
        'message': 'Application rejected' + (' and email sent' if email_sent else ' but email failed to send')
    })
    
def send_inspection_notifications(inspection_data, business_data, inspector_data):
    try:
        # Send notification to user/business owner
        user_subject = "Upcoming Fire Safety Inspection Scheduled"
        user_body = f"""
Dear {business_data.get('contact_person', 'Business Owner')},

A fire safety inspection has been scheduled for your business:

Business Details:
- Name: {business_data['business_name']}
- Address: {business_data['business_address']}

Inspection Details:
- Date: {inspection_data['date']}
- Time: {inspection_data['time']}
- Inspector: {inspector_data['name']}

Please ensure all necessary personnel are available during the inspection.

Best regards,
Fire Safety Department
"""
        # Send email to business owner
        send_email(user_subject, business_data['email'], user_body)

        # Send notification to inspector with activation link
        inspector_subject = "New Inspection Assignment"
        activation_token = secrets.token_urlsafe(32)
        activation_link = f"{request.host_url}activate_inspection/{inspection_data['_id']}/{activation_token}"
        
        inspector_body = f"""
Dear {inspector_data['name']},

You have been assigned a new fire safety inspection:

Business Details:
- Name: {business_data['business_name']}
- Address: {business_data['business_address']}
- Contact Person: {business_data.get('contact_person', 'N/A')}
- Contact Number: {business_data.get('contact_number', 'N/A')}

Inspection Schedule:
- Date: {inspection_data['date']}
- Time: {inspection_data['time']}
- Location: {inspection_data.get('location', 'As per business address')}

Click the following link to activate and start the inspection:
{activation_link}

Please note: Activate the inspection only when you arrive at the location.

Best regards,
Fire Safety Department
"""
        # Save activation token
        inspections.update_one(
            {'_id': inspection_data['_id']},
            {'$set': {
                'activation_token': activation_token,
                'activated': False
            }}
        )

        # Send email to inspector
        send_email(inspector_subject, inspector_data['email'], inspector_body)

        return True

    except Exception as e:
        print(f"Error sending inspection notifications: {str(e)}")
        return False

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
                      choices=[('admin', 'Admin'), ('user', 'User'), 
                              ('inspector', 'Inspector')])
    aadhaar_photo = FileField('Aadhaar Card Photo', validators=[InputRequired()])
    submit = SubmitField('Register')

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if (form.validate_on_submit()):
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
            # Handle Aadhaar photo upload
            aadhaar_photo = form.aadhaar_photo.data
            if aadhaar_photo:
                filename = secure_filename(f"aadhaar_{form.username.data}_{int(time.time())}.jpg")
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                aadhaar_photo.save(filepath)
                
                # Extract Aadhaar number and verify
                extracted_aadhaar = extract_aadhaar(filepath)
                if extracted_aadhaar:
                    # Check if Aadhaar exists in dataset
                    name, phone = find_user_by_aadhaar(extracted_aadhaar)
                    if name:
                        # Create user without name verification
                        hashed_password = bcrypt.hashpw(
                            form.password.data.encode('utf-8'), 
                            bcrypt.gensalt()
                        )
                        user_data = {
                            'username': form.username.data,
                            'name': form.name.data,  # Use provided name
                            'email': form.email.data,
                            'password': hashed_password,
                            'role': form.role.data,
                            'aadhaar_number': extracted_aadhaar,
                            'aadhaar_photo': filename,
                            'phone': phone,
                            'created_at': datetime.now()
                        }
                        users.insert_one(user_data)
                        
                        # Send registration email
                        send_registration_email(user_data)
                        
                        log_activity('Registration', f"New user registered: {form.username.data}")
                        flash('Registration successful! Please check your email.', 'success')
                        return redirect(url_for('login'))
                    else:
                        flash('Aadhaar number not found in our records!', 'danger')
                        os.remove(filepath)  # Remove uploaded file
                else:
                    flash('Could not extract Aadhaar number from the uploaded image!', 'danger')
                    os.remove(filepath)  # Remove uploaded file
            else:
                flash('Please upload your Aadhaar card photo!', 'danger')
    
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
        # Create uploads directory if it doesn't exist
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])

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

        # Validate required fields
        required_fields = ['business_name', 'business_type', 'business_address', 'contact_number']
        for field in required_fields:
            if not application_data.get(field):
                return jsonify({'error': f'{field.replace("_", " ").title()} is required'}), 400

        # Handle file uploads
        files = {}
        file_types = ['buildingPlan', 'safetyCertificate', 'insuranceDoc']
        
        for file_type in file_types:
            if file_type in request.files:
                file = request.files[file_type]
                if file and file.filename and allowed_file(file.filename):
                    # Create a secure filename with timestamp
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    filename = f"{timestamp}_{secure_filename(file.filename)}"
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    
                    # Save the file
                    file.save(file_path)
                    files[file_type] = filename
                    
                    # Optional: Perform document content detection
                    if file_type in ['buildingPlan', 'safetyCertificate']:
                        extracted_text, errors = detect_document_content(file_path)
                        if errors:
                            return jsonify({'error': f'Document validation failed: {", ".join(errors)}'}), 400

        # Add files to application data
        application_data['files'] = files

        # Insert application into database
        result = applications.insert_one(application_data)
        
        # Send confirmation email to applicant
        send_application_confirmation_email(application_data, result.inserted_id)
        
        # Send notification to admin
        admin_notification = f'''New NOC application received:
Business Name: {application_data['business_name']}
Business Type: {application_data['business_type']}
Application ID: {str(result.inserted_id)}
Submitted By: {session['username']}
Contact: {application_data['contact_number']}

You can review the application at:
{url_for('view_application', application_id=str(result.inserted_id), _external=True)}
'''
        
        send_email(
            'New NOC Application Submitted',
            app.config['MAIL_USERNAME'],
            admin_notification
        )

        # Log activity
        log_activity(
            'Application Submitted',
            f"New NOC application submitted for: {application_data['business_name']}"
        )
        
        # Send email notification
        try:
            admin_notification = f'''New NOC application received:
Business Name: {application_data['business_name']}
Business Type: {application_data['business_type']}
Application ID: {str(result.inserted_id)}'''
            
            send_email(
                'New NOC Application Submitted',
                app.config['MAIL_USERNAME'],  # Admin email
                admin_notification
            )
        except Exception as e:
            # Log email error but don't fail the submission
            print(f"Error sending email notification: {e}")

        # Emit socket.io event for real-time updates
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
        app.logger.error(f"Error submitting application: {str(e)}")
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

@app.route('/approve_application/<application_id>', methods=['POST'])
def approve_application(application_id):
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        # Get application details
        application = applications.find_one({'_id': ObjectId(application_id)})
        if not application:
            return jsonify({'error': 'Application not found'}), 404

        # Update application status
        result = applications.update_one(
            {'_id': ObjectId(application_id)},
            {'$set': {
                'status': 'approved',
                'approved_by': session['username'],
                'approved_at': datetime.now(),
                'valid_until': datetime.now() + timedelta(days=365)
            }}
        )
        
        if result.modified_count == 0:
            return jsonify({'error': 'Failed to approve application'}), 500

        # Generate NOC report
        report_buffer = generate_noc_report(application, application_id)
        
        # Send approval email with NOC certificate
        subject = "NOC Application Approved - Certificate Attached"
        body = f"""
Dear {application.get('name', 'Applicant')},

Your NOC application has been APPROVED.

Application Details:
- Application ID: {str(application['_id'])}
- Business Name: {application.get('business_name')}
- Submission Date: {application.get('timestamp', datetime.now()).strftime('%Y-%m-%d %H:%M:%S')}
- Approved By: {session.get('username')}
- Approval Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- Valid Until: {(datetime.now() + timedelta(days=365)).strftime('%Y-%m-%d')}

Please find your NOC certificate attached to this email.
You can also view and download your certificate by logging into your dashboard:
{url_for('view_application', application_id=str(application['_id']), _external=True)}

Best regards,
Fire Safety Department
"""
        try:
            msg = Message(
                subject,
                sender=app.config['MAIL_USERNAME'],
                recipients=[application.get('email')]
            )
            msg.body = body
            
            # Attach the PDF report
            report_buffer.seek(0)
            msg.attach(
                f"NOC_Certificate_{application.get('business_name', 'Business')}.pdf",
                "application/pdf",
                report_buffer.read()
            )
            
            mail.send(msg)
            email_sent = True
        except Exception as e:
            print(f"Error sending approval email: {str(e)}")
            email_sent = False

        # Log activity
        log_activity(
            'Application Approval',
            f"Application {application_id} approved and {'email sent' if email_sent else 'email failed'}"
        )
        
        # Emit socket event
        socketio.emit('application_status_changed', {
            'application_id': str(application_id),
            'status': 'approved',
            'message': 'Application has been approved!'
        })
        
        return jsonify({
            'success': True, 
            'message': 'Application approved' + (' and email sent' if email_sent else ' but email failed to send')
        })
    
    except Exception as e:
        print(f"Error in approve_application: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/reject_application/<application_id>', methods=['POST'])
def reject_application(application_id):
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        data = request.get_json()
        rejection_reason = data.get('rejection_reason')
        
        if not rejection_reason:
            return jsonify({'error': 'Rejection reason is required'}), 400
        
        # Get application details
        application = applications.find_one({'_id': ObjectId(application_id)})
        if not application:
            return jsonify({'error': 'Application not found'}), 404
        
        # Update application status
        result = applications.update_one(
            {'_id': ObjectId(application_id)},
            {'$set': {
                'status': 'rejected',
                'rejected_by': session['username'],
                'rejected_at': datetime.now(),
                'rejection_reason': rejection_reason
            }}
        )
        
        if result.modified_count == 0:
            return jsonify({'error': 'Failed to reject application'}), 500
        
        # Send rejection email
        subject = "NOC Application Rejected"
        body = f"""
Dear {application.get('name', 'Applicant')},

Your NOC application has been REJECTED.

Application Details:
- Application ID: {str(application['_id'])}
- Business Name: {application.get('business_name')}
- Submission Date: {application.get('timestamp', datetime.now()).strftime('%Y-%m-%d %H:%M:%S')}
- Rejected By: {session.get('username')}
- Rejection Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Business Information:
- Address: {application.get('business_address')}
- Contact Number: {application.get('contact_number')}

Reason for Rejection:
{rejection_reason}

You can submit a new application after addressing the above concerns.
Please log in to your dashboard for more details.

Best regards,
Fire Safety Department
"""
        try:
            msg = Message(
                subject,
                sender=app.config['MAIL_USERNAME'],
                recipients=[application.get('email')]
            )
            msg.body = body
            mail.send(msg)
            email_sent = True
        except Exception as e:
            print(f"Error sending rejection email: {str(e)}")
            email_sent = False

        # Log activity
        log_activity(
            'Application Rejection',
            f"Application {application_id} rejected and {'email sent' if email_sent else 'email failed'}"
        )
        
        # Emit socket event
        socketio.emit('application_status_changed', {
            'application_id': str(application_id),
            'status': 'rejected',
            'message': 'Application has been rejected!'
        })
        
        return jsonify({
            'success': True, 
            'message': 'Application rejected' + (' and email sent' if email_sent else ' but email failed to send')
        })
    
    except Exception as e:
        print(f"Error in reject_application: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/application/<application_id>/update-status', methods=['POST'])
@csrf.exempt  # If you want to handle CSRF manually
def update_application_status(application_id):
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        new_status = data.get('status')
        reason = data.get('reason', '')

        if new_status not in ['approved', 'rejected', 'pending']:
            return jsonify({'error': 'Invalid status'}), 400

        current_time = datetime.now()
        
        # Prepare update data
        update_data = {
            'status': new_status,
            'updated_at': current_time,
            'updated_by': session.get('username')
        }

        if new_status == 'approved':
            valid_until = current_time + timedelta(days=365)
            update_data.update({
                'approval_date': current_time,
                'approved_by': session.get('username'),
                'valid_until': valid_until
            })
        elif new_status == 'rejected':
            update_data.update({
                'rejection_date': current_time,
                'rejected_by': session.get('username'),
                'rejection_reason': reason
            })

        # Update application
        result = applications.update_one(
            {'_id': ObjectId(application_id)},
            {'$set': update_data}
        )

        if result.modified_count == 0:
            return jsonify({'error': 'Application not found'}), 404

        # Get the updated application
        updated_app = applications.find_one({'_id': ObjectId(application_id)})
        
        # Send notification via WebSocket
        socketio.emit('application_updated', {
            'applicationId': application_id,
            'status': new_status
        })

        return jsonify({
            'success': True,
            'message': f'Application {new_status} successfully',
            'application': {
                'id': str(updated_app['_id']),
                'status': new_status,
                'updated_at': current_time.isoformat()
            }
        })

    except Exception as e:
        app.logger.error(f"Error updating application status: {str(e)}")
        return jsonify({'error': str(e)}), 500

def generate_approval_report(application):
    """Generate a structured report for approved applications"""
    current_time = datetime.now()
    valid_until = current_time + timedelta(days=365)
    
    return {
        'report_id': str(ObjectId()),
        'application_id': str(application['_id']),
        'business_name': application.get('business_name'),
        'business_type': application.get('business_type'),
        'business_address': application.get('business_address'),
        'approval_details': {
            'approved_by': session['username'],
            'approval_date': current_time,
            'valid_until': valid_until
        },
        'safety_compliance': {
            'fire_extinguishers': application.get('fire_extinguishers'),
            'fire_alarm': application.get('fire_alarm'),
            'emergency_exits': application.get('emergency_exits'),
            'last_fire_drill': application.get('last_fire_drill')
        },
        'approval_conditions': [
            'Regular maintenance of fire safety equipment required',
            'Monthly fire drills mandatory',
            'Annual safety audit to be conducted',
            'Immediate reporting of any safety incidents'
        ],
        'timestamp': current_time
    }

def send_status_notification_email(application, status, reason=''):
    """Send email notification for application status updates"""
    subject = f'NOC Application {status.capitalize()}'
    
    if status == 'approved':
        body = f"""
        Your NOC application has been APPROVED.
        
        Application Details:
        - Application ID: {str(application['_id'])}
        - Business Name: {application.get('business_name')}
        - Approved By: {session['username']}
        - Approval Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        - Valid Until: {(datetime.now() + timedelta(days=365)).strftime('%Y-%m-%d')}
        
        Please log in to your dashboard to view and download your NOC certificate.
        """
    else:
        body = f"""
        Your NOC application has been REJECTED.
        
        Application Details:
        - Application ID: {str(application['_id'])}
        - Business Name: {application.get('business_name')}
        - Rejected By: {session['username']}
        - Rejection Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        - Reason: {reason}
        
        Please log in to your dashboard for more details or to submit a revised application.
        """
    
    send_email(subject, application['email'], body)

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

@app.route('/view_application/<application_id>')
def view_application(application_id):
    if 'username' not in session:
        flash('Please log in first!', 'danger')
        return redirect(url_for('login'))
    
    try:
        application = applications.find_one({'_id': ObjectId(application_id)})
        if not application:
            flash('Application not found!', 'danger')
            return redirect(url_for('manage_applications'))
        
        # Add created_at if it doesn't exist
        if 'created_at' not in application:
            application['created_at'] = application.get('timestamp', datetime.now())
        
        # Add approved_by if it doesn't exist
        if 'status' in application and application['status'] == 'approved':
            if 'approved_by' not in application:
                application['approved_by'] = application.get('last_modified_by', 'Admin')
        
        # Convert ObjectId to string for JSON serialization
        application['_id'] = str(application['_id'])
        
        # Get report if application is approved
        report = None
        if application.get('status') == 'approved':
            report = reports.find_one({'application_id': application_id})
            if report:
                report['_id'] = str(report['_id'])
        
        return render_template('view_application.html', 
                             application=application,
                             report=report)
                             
    except Exception as e:
        print(f"Error in view_application: {str(e)}")
        flash('Error loading application!', 'danger')
        return redirect(url_for('manage_applications'))

@app.route('/approval-report/<report_id>')
def view_approval_report(report_id):
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    try:
        report = reports.find_one({'_id': ObjectId(report_id)})
        if not report:
            return jsonify({'error': 'Report not found'}), 404
            
        # Get the associated application
        application = applications.find_one({'_id': ObjectId(report['application_id'])})
        if not application:
            return jsonify({'error': 'Associated application not found'}), 404
            
        # Add required fields if they don't exist
        report['created_at'] = report.get('created_at', application.get('approved_date', datetime.now()))
        report['approved_by'] = report.get('approved_by', application.get('approved_by', 'Admin'))
        
        # Convert ObjectId to string
        report['_id'] = str(report['_id'])
        report['application_id'] = str(report['application_id'])
        
        return jsonify(report)
        
    except Exception as e:
        print(f"Error in view_approval_report: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/manage_applications')
def manage_applications():
    if 'username' not in session:
        flash('Please log in first!', 'danger')
        return redirect(url_for('login'))
    
    all_applications = list(applications.find().sort('timestamp', -1))
    return render_template('manage_applications.html', applications=all_applications)

@app.route('/manage_users')
def manage_users():
    if 'username' not in session or session['role'] != 'admin':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('login'))
    
    all_users = list(users.find({}, {
        'password': 0  # Exclude password from results
    }))
    
    return render_template('manage_users.html', users=all_users)

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

        # Handle expert status update
        if 'is_expert' in updated_data:
            updated_data['is_expert'] = bool(updated_data['is_expert'])
            # Log expert status change
            log_activity(
                'User Update', 
                f"User {updated_data.get('username')} {'set as expert' if updated_data['is_expert'] else 'removed from expert'} by {session['username']}"
            )

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

# Add these routes to handle user dashboard data
@app.route('/api/user-data')
def get_user_data():
    if 'username' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    try:
        # Get user details
        user = users.find_one({'username': session['username']})
        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Get application counts
        pending_count = applications.count_documents({
            'username': session['username'],
            'status': 'pending'
        })
        approved_count = applications.count_documents({
            'username': session['username'],
            'status': 'approved'
        })
        
        # Get upcoming inspections count
        upcoming_inspections = 0  # You can implement this based on your needs

        return jsonify({
            'user': {
                'name': user.get('name', ''),
                'email': user.get('email', ''),
                'role': user.get('role', '')
            },
            'stats': {
                'pending_applications': pending_count,
                'approved_applications': approved_count,
                'upcoming_inspections': upcoming_inspections
            }
        })
    except Exception as e:
        app.logger.error(f"Error fetching user data: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/user-applications')
def get_user_applications():
    if 'username' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    try:
        user_applications = list(applications.find(
            {'username': session['username']}
        ).sort('timestamp', -1))
        
        # Convert ObjectIds to strings and format dates
        for app in user_applications:
            app['_id'] = str(app['_id'])
            if 'timestamp' in app:
                app['timestamp'] = app['timestamp'].isoformat()
            if 'approval_date' in app:
                app['approval_date'] = app['approval_date'].isoformat()
            if 'valid_until' in app:
                app['valid_until'] = app['valid_until'].isoformat()
        
        return jsonify({'applications': user_applications})
    except Exception as e:
        app.logger.error(f"Error fetching user applications: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/approval-reports')
def get_approval_reports():
    if 'username' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    try:
        # Get all approved applications for the user
        approved_apps = list(applications.find({
            'username': session['username'],
            'status': 'approved'
        }).sort('approval_date', -1))
        
        reports_data = []
        for app in approved_apps:
            report = {
                'report_id': str(app['_id']),
                'business_name': app.get('business_name', ''),
                'business_type': app.get('business_type', ''),
                'business_address': app.get('business_address', ''),
                'approval_details': {
                    'approved_by': app.get('approved_by', ''),
                    'approval_date': app.get('approval_date', datetime.now()).isoformat(),
                    'valid_until': app.get('valid_until', datetime.now() + timedelta(days=365)).isoformat()
                },
                'safety_compliance': {
                    'fire_extinguishers': app.get('fire_extinguishers', ''),
                    'fire_alarm': app.get('fire_alarm', ''),
                    'emergency_exits': app.get('emergency_exits', ''),
                    'last_fire_drill': app.get('last_fire_drill', '')
                },
                'approval_conditions': [
                    'Regular maintenance of fire safety equipment required',
                    'Monthly fire drills mandatory',
                    'Annual safety audit to be conducted',
                    'Immediate reporting of any safety incidents'
                ]
            }
            reports_data.append(report)
        
        return jsonify({'reports': reports_data})
    except Exception as e:
        app.logger.error(f"Error fetching approval reports: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/approval-report/<report_id>')
def get_approval_report(report_id):
    if 'username' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    try:
        application = applications.find_one({
            '_id': ObjectId(report_id),
            'username': session['username']
        })
        
        if not application:
            return jsonify({'error': 'Report not found'}), 404
            
        report = {
            'report_id': str(application['_id']),
            'business_name': application.get('business_name', ''),
            'business_type': application.get('business_type', ''),
            'business_address': application.get('business_address', ''),
            'approval_details': {
                'approved_by': application.get('approved_by', ''),
                'approval_date': application.get('approval_date', datetime.now()).isoformat(),
                'valid_until': application.get('valid_until', datetime.now() + timedelta(days=365)).isoformat()
            },
            'safety_compliance': {
                'fire_extinguishers': application.get('fire_extinguishers', ''),
                'fire_alarm': application.get('fire_alarm', ''),
                'emergency_exits': application.get('emergency_exits', ''),
                'last_fire_drill': application.get('last_fire_drill', '')
            },
            'approval_conditions': [
                'Regular maintenance of fire safety equipment required',
                'Monthly fire drills mandatory',
                'Annual safety audit to be conducted',
                'Immediate reporting of any safety incidents'
            ]
        }
        
        return jsonify(report)
        
    except Exception as e:
        app.logger.error(f"Error fetching report details: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Add these indexes to your MongoDB collections
applications.create_index([('status', 1)])
applications.create_index([('timestamp', -1)])
applications.create_index([('business_name', 1)])

@app.route('/api/all-applications')
def get_all_applications():
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        # Get all applications with user details
        pipeline = [
            {
                '$lookup': {
                    'from': 'users',
                    'localField': 'username',
                    'foreignField': 'username',
                    'as': 'user_details'
                }
            },
            {
                '$sort': {'timestamp': -1}
            }
        ]
        
        all_applications = list(applications.aggregate(pipeline))
        
        # Process the applications to handle ObjectId and datetime
        processed_applications = []
        for app in all_applications:
            processed_app = {
                '_id': str(app['_id']),
                'business_name': app.get('business_name', ''),
                'business_type': app.get('business_type', ''),
                'status': app.get('status', 'pending'),
                'timestamp': app.get('timestamp', datetime.now()).strftime('%Y-%m-%d %H:%M:%S'),
                'email': app.get('email', ''),
                'phone': app.get('phone', ''),
                'address': app.get('address', ''),
                'username': app.get('username', ''),
                'report_id': str(app.get('report_id')) if app.get('report_id') else None
            }
            
            # Add formatted dates if they exist
            if 'approval_date' in app:
                processed_app['approval_date'] = app['approval_date'].strftime('%Y-%m-%d %H:%M:%S')
            if 'valid_until' in app:
                processed_app['valid_until'] = app['valid_until'].strftime('%Y-%m-%d')
            if 'rejection_date' in app:
                processed_app['rejection_date'] = app['rejection_date'].strftime('%Y-%m-%d %H:%M:%S')
                
            # Add user details
            if app.get('user_details'):
                user = app['user_details'][0]
                processed_app['user_details'] = {
                    'name': user.get('name', ''),
                    'email': user.get('email', '')
                }
                
            processed_applications.append(processed_app)
        
        return jsonify({'applications': processed_applications})
        
    except Exception as e:
        app.logger.error(f"Error in get_all_applications: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/approved-reports')
def get_admin_approved_reports():
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        # Get all approved applications
        approved_apps = list(applications.find({
            'status': 'approved'
        }).sort('approval_date', -1))
        
        reports_data = []
        for app in approved_apps:
            report = {
                'report_id': str(app['_id']),
                'business_name': app.get('business_name', ''),
                'business_type': app.get('business_type', ''),
                'business_address': app.get('business_address', ''),
                'approval_details': {
                    'approved_by': app.get('approved_by', ''),
                    'approval_date': app.get('approval_date', datetime.now()).isoformat(),
                    'valid_until': app.get('valid_until', datetime.now() + timedelta(days=365)).isoformat()
                }
            }
            reports_data.append(report)
        
        return jsonify({'reports': reports_data})
    except Exception as e:
        app.logger.error(f"Error fetching approved reports: {str(e)}")
        return jsonify({'error': str(e)}), 500

def create_default_logo():
    # Create directory if it doesn't exist
    logo_dir = os.path.join('static', 'images')
    if not os.path.exists(logo_dir):
        os.makedirs(logo_dir)
    
    logo_path = os.path.join(logo_dir, 'fire_logo.png')
    
    # Create default logo if it doesn't exist
    if not os.path.exists(logo_path):
        # Create a new image with a white background
        img = Image.new('RGB', (200, 200), 'white')
        draw = ImageDraw.Draw(img)
        
        # Draw a red circle
        draw.ellipse([20, 20, 180, 180], fill='red')
        
        # Add text
        try:
            font = ImageFont.truetype('arial.ttf', 40)
        except:
            font = ImageFont.load_default()
            
        draw.text((100, 100), 'FIRE\nNOC', font=font, fill='white', 
                 anchor='mm', align='center')
        
        # Save the image
        img.save(logo_path, 'PNG')
    
    return logo_path

def generate_noc_report(application_data, report_id):
    try:
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=72)

        # Styles setup
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(
            name='CustomTitle',
            fontName='Helvetica-Bold',
            fontSize=24,
            spaceAfter=30,
            alignment=1,
            textColor=colors.HexColor('#1a237e')
        ))
        
        styles.add(ParagraphStyle(
            name='SectionTitle',
            fontName='Helvetica-Bold',
            fontSize=14,
            spaceAfter=10,
            textColor=colors.HexColor('#0d47a1')
        ))

        styles.add(ParagraphStyle(
            name='NormalText',
            fontName='Helvetica',
            fontSize=10,
            spaceAfter=6,
            textColor=colors.HexColor('#000000')
        ))

        elements = []

        # Logo and Title
        try:
            logo_path = create_default_logo()
            logo = Image(logo_path, width=2*inch, height=2*inch)
            logo.hAlign = 'CENTER'
            elements.append(logo)
        except:
            pass
        
        elements.append(Spacer(1, 20))
        elements.append(Paragraph('FIRE SAFETY CERTIFICATE', styles['CustomTitle']))
        
        # Certificate Details
        cert_details = [
            ['Certificate Number:', f'FSC-{report_id}'],
            ['Application ID:', str(application_data.get('application_id', ''))],
            ['Report ID:', str(application_data.get('report_id', ''))],
            ['Issue Date:', datetime.now().strftime('%d-%m-%Y')],
            ['Valid Until:', (datetime.now() + timedelta(days=365)).strftime('%d-%m-%Y')]
        ]
        
        cert_table = Table(cert_details, colWidths=[2.5*inch, 4*inch])
        cert_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f5f5f5')),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#1a237e')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e0e0e0'))
        ]))
        elements.append(cert_table)
        elements.append(Spacer(1, 20))

        # Business Information
        elements.append(Paragraph('Business Information', styles['SectionTitle']))
        business_data = [
            ['Business Name:', application_data.get('business_name', '')],
            ['Business Type:', application_data.get('business_type', '')],
            ['Business Address:', application_data.get('business_address', '')],
            ['Contact Person:', application_data.get('contact_person', '')],
            ['Contact Number:', application_data.get('contact_number', '')],
            ['Email Address:', application_data.get('email', '')],
            ['Building Type:', application_data.get('building_type', '')],
            ['Building Area:', f"{application_data.get('building_area', '')} sq.ft"],
            ['Number of Floors:', application_data.get('num_floors', '')],
            ['Operating Hours:', application_data.get('operating_hours', '')],
            ['Maximum Occupancy:', application_data.get('max_occupancy', '')],
            ['Registration Number:', application_data.get('registration_number', '')]
        ]
        
        business_table = Table(business_data, colWidths=[2.5*inch, 4*inch])
        business_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f5f5f5')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e0e0e0'))
        ]))
        elements.append(business_table)
        elements.append(Spacer(1, 20))

        # Approval Details
        elements.append(Paragraph('Approval Information', styles['SectionTitle']))
        approval_details = application_data.get('approval_details', {})
        approval_data = [
            ['Approved By:', approval_details.get('approved_by', '')],
            ['Approval Date:', approval_details.get('approval_date', '').strftime('%d-%m-%Y') if approval_details.get('approval_date') else ''],
            ['Valid Until:', approval_details.get('valid_until', '').strftime('%d-%m-%Y') if approval_details.get('valid_until') else '']
        ]
        
        approval_table = Table(approval_data, colWidths=[2.5*inch, 4*inch])
        approval_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f5f5f5')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e0e0e0'))
        ]))
        elements.append(approval_table)
        elements.append(Spacer(1, 20))

        # Safety Compliance
        elements.append(Paragraph('Safety Compliance Details', styles['SectionTitle']))
        safety_compliance = application_data.get('safety_compliance', {})
        safety_data = [
            ['Fire Extinguishers:', str(safety_compliance.get('fire_extinguishers', ''))],
            ['Fire Alarm System:', str(safety_compliance.get('fire_alarm', ''))],
            ['Emergency Exits:', str(safety_compliance.get('emergency_exits', ''))],
            ['Last Fire Drill:', str(safety_compliance.get('last_fire_drill', ''))]
        ]
        
        safety_table = Table(safety_data, colWidths=[2.5*inch, 4*inch])
        safety_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f5f5f5')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e0e0e0'))
        ]))
        elements.append(safety_table)
        elements.append(Spacer(1, 20))

        # QR Code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(f"Certificate Verification: FSC-{report_id}")
        qr.make(fit=True)
        qr_img = qr.make_image(fill_color="black", back_color="white")
        qr_buffer = BytesIO()
        qr_img.save(qr_buffer)
        qr_buffer.seek(0)
        
        qr_image = Image(qr_buffer)
        qr_image.drawHeight = 1.5*inch
        qr_image.drawWidth = 1.5*inch
        qr_image.hAlign = 'RIGHT'
        elements.append(qr_image)

        # Signatures
        signature_data = [
            ['_____________________', '_____________________', '_____________________'],
            ['Fire Safety Officer', 'Chief Fire Officer', 'Date'],
            [
                approval_details.get('approved_by', ''),
                'Chief Officer',
                datetime.now().strftime('%d-%m-%Y')
            ]
        ]
        
        signature_table = Table(signature_data, colWidths=[2*inch, 2*inch, 2*inch])
        signature_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 1), (-1, 1), 'Helvetica-Bold')
        ]))
        elements.append(signature_table)

        # Build PDF
        doc.build(elements)
        return buffer

    except Exception as e:
        print(f"Error generating PDF: {str(e)}")
        raise

@app.route('/download-report/<report_id>')
def download_report(report_id):
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    try:
        # Get application data
        application = applications.find_one({'_id': ObjectId(report_id)})
        if not application:
            flash('Report not found', 'error')
            return redirect(url_for('dashboard'))

        # Generate the report
        pdf_buffer = generate_noc_report(application, report_id)
        if not pdf_buffer:
            flash('Failed to generate report', 'error')
            return redirect(url_for('dashboard'))
            
        pdf_buffer.seek(0)
        
        # Generate a filename with business name and timestamp
        business_name = application.get('business_name', '').replace(' ', '_')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"NOC_Certificate_{business_name}_{timestamp}.pdf"
        
        # Read the PDF data into memory
        pdf_data = pdf_buffer.getvalue()
        pdf_buffer.close()  # Close the original buffer
        
        # Create a new BytesIO object with the PDF data
        final_buffer = BytesIO(pdf_data)
        final_buffer.seek(0)
        
        # Send file with proper headers for PDF
        response = send_file(
            final_buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename,
            conditional=True  # Enable conditional responses
        )
        
        # Add headers to prevent caching and ensure proper PDF handling
        response.headers["Content-Type"] = "application/pdf"
        response.headers["Content-Disposition"] = f"attachment; filename={filename}"
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, post-check=0, pre-check=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        
        return response

    except Exception as e:
        print(f"Download error: {str(e)}")
        flash('Failed to generate report', 'error')
        return redirect(url_for('dashboard'))

@app.route('/get-report-url/<report_id>')
def get_report_url(report_id):
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        return jsonify({
            'download_url': url_for('download_report', report_id=report_id),
            'view_url': url_for('view_report', report_id=report_id)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/user_activities')
def user_activities():
    if 'username' not in session:
        flash('Please log in first!', 'danger')
        return redirect(url_for('login'))
        
    try:
        # Get all activities with proper field handling
        all_activities = list(activities.find().sort('timestamp', -1))
        
        # Add missing fields and format timestamps
        for activity in all_activities:
            # Convert ObjectId to string
            activity['_id'] = str(activity['_id'])
            
            # Ensure timestamp exists
            if 'timestamp' not in activity:
                activity['timestamp'] = datetime.now()
                
            # Ensure username exists
            if 'username' not in activity:
                activity['username'] = 'System'
                
            # Ensure activity_type exists
            if 'activity_type' not in activity:
                activity['activity_type'] = 'general'
                
            # Ensure description exists
            if 'description' not in activity:
                activity['description'] = 'No description available'
        
        return render_template('user_activities.html', activities=all_activities)
        
    except Exception as e:
        print(f"Error in user_activities: {str(e)}")
        flash('Error loading activities!', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/api/user_activities')
def get_user_activities():
    try:
        # Get all activities with pagination
        page = int(request.args.get('page', 1))
        per_page = 20
        skip = (page - 1) * per_page
        
        all_activities = list(activities.find().sort('timestamp', -1).skip(skip).limit(per_page))
        total = activities.count_documents({})
        
        return jsonify({
            'activities': dumps(all_activities),
            'total': total,
            'page': page,
            'pages': (total + per_page - 1) // per_page
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/profile/<username>')
def view_profile(username):
    if 'username' not in session:
        flash('Please log in first!', 'danger')
        return redirect(url_for('login'))
    
    user = users.find_one({'username': username})
    if not user:
        flash('User not found!', 'danger')
        return redirect(url_for('dashboard'))

    # Check permissions
    if session['username'] != username and session['role'] != 'admin':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get role-specific data
    role_data = get_role_specific_data(user)
    
    return render_template('profile.html', user=user, role_data=role_data)

def get_role_specific_data(user):
    try:
        role = user.get('role', '')
        username = user.get('username', '')
        
        if role == 'user':
            return {
                'total_applications': applications.count_documents({'username': username}),
                'approved_applications': applications.count_documents({'username': username, 'status': 'approved'}),
                'pending_applications': applications.count_documents({'username': username, 'status': 'pending'}),
                'recent_applications': list(applications.find(
                    {'username': username}
                ).sort('timestamp', -1).limit(5)),
                'recent_activities': list(activities.find(
                    {'username': username}
                ).sort('timestamp', -1).limit(5))
            }
        
        elif role == 'admin':
            return {
                'total_users': users.count_documents({}),
                'total_applications': applications.count_documents({}),
                'system_stats': {
                    'pending_applications': applications.count_documents({'status': 'pending'}),
                    'approved_applications': applications.count_documents({'status': 'approved'}),
                    'rejected_applications': applications.count_documents({'status': 'rejected'})
                }
            }
        
        elif role == 'inspector':
            return {
                'assigned_inspections': inspections.count_documents({'inspector_id': username}),
                'completed_inspections': inspections.count_documents({
                    'inspector_id': username,
                    'status': 'completed'
                }),
                'recent_inspections': list(inspections.find(
                    {'inspector_id': username}
                ).sort('date', -1).limit(5))
            }
            
        return {}
        
    except Exception as e:
        print(f"[ERROR] Error getting role data: {str(e)}")
        return {}

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        flash('Please log in first!', 'danger')
        return redirect(url_for('login'))
    
    user = users.find_one({'username': session['username']})
    role = user['role']
    
    if role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif role == 'user':
        return redirect(url_for('user_dashboard'))
    elif role == 'inspector':
        return redirect(url_for('inspector_dashboard'))
    
    flash('Invalid role!', 'danger')
    return redirect(url_for('login'))

@app.route('/profile/update', methods=['POST'])
def update_profile():
    if 'username' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    try:
        data = request.form.to_dict()
        user = users.find_one({'username': session['username']})
        role = user['role']
        
        # Base profile update data
        update_data = {
            'name': data.get('name'),
            'email': data.get('email'),
            'mobile': data.get('mobile'),
            'address': data.get('address'),
            'updated_at': datetime.now()
        }
        
        # Role-specific profile updates
        if role == 'user':
            update_data.update({
                'company_name': data.get('company_name'),
                'business_type': data.get('business_type'),
                'gst_number': data.get('gst_number'),
                'business_address': data.get('business_address')
            })
        elif role == 'admin':
            update_data.update({
                'department': data.get('department'),
                'designation': data.get('designation'),
                'team_size': data.get('team_size')
            })
        elif role == 'inspector':
            update_data.update({
                'department': data.get('department'),
                'designation': data.get('designation'),
                'skills': data.get('skills', '').split(',')
            })
        
        # Handle profile image upload
        if 'profile_image' in request.files:
            file = request.files['profile_image']
            if file and file.filename and allowed_file(file.filename):
                # Create a secure filename with timestamp
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"{session['username']}_{int(time.time())}{os.path.splitext(file.filename)[1]}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                
                # Save the file
                file.save(file_path)
                update_data['profile_image'] = filename
        
        # Update user document
        users.update_one(
            {'username': session['username']},
            {'$set': update_data}
        )
        
        # Log activity
        log_activity('Profile Update', f"User {session['username']} updated their profile")
        
        return jsonify({
            'success': True,
            'message': 'Profile updated successfully!',
            'redirect': url_for('view_profile', username=session['username'])
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin_profile')
def admin_profile():
    if 'username' not in session:
        flash('Please log in first!', 'danger')
        return redirect(url_for('login'))
        
    if session.get('role') != 'admin':
        flash('Access denied!', 'danger')
        return redirect(url_for('dashboard'))
        
    user = users.find_one({'username': session['username']})
    if not user:
        flash('User not found!', 'danger')
        return redirect(url_for('admin_dashboard'))
        
    return render_template('admin_profile.html', user=user)

@app.route('/api/admin/profile/update', methods=['POST'])
def api_admin_profile_update():
    if 'username' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'Access denied!'})
        
    try:
        data = request.get_json()
        
        # Update user document
        result = users.update_one(
            {'username': session['username']},
            {'$set': {
                'name': data.get('name'),
                'email': data.get('email'),
                'phone': data.get('phone'),
                'updated_at': datetime.now()
            }}
        )
        
        if result.modified_count == 0:
            return jsonify({'success': False, 'error': 'No changes made'}), 400
            
        return jsonify({
            'success': True,
            'name': data.get('name'),
            'email': data.get('email'),
            'phone': data.get('phone')
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/admin/profile/update_image', methods=['POST'])
def api_admin_profile_update_image():
    if 'username' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'Access denied!'})
        
    try:
        if 'profile_image' not in request.files:
            return jsonify({'success': False, 'error': 'No file provided'}), 400
            
        file = request.files['profile_image']
        
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400
            
        if not allowed_file(file.filename):
            return jsonify({'success': False, 'error': 'Invalid file type'}), 400
        
        # Create a secure filename with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{session['username']}_{timestamp}_{secure_filename(file.filename)}"
        
        # Save the file
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Update user document with new image path
        users.update_one(
            {'username': session['username']},
            {'$set': {
                'profile_image': filename,
                'updated_at': datetime.now()
            }}
        )
        
        # Delete old profile image if it exists and is not the default
        old_image = users.find_one({'username': session['username']}).get('profile_image')
        if old_image and old_image != 'default-profile.png':
            old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], old_image)
            if os.path.exists(old_image_path):
                os.remove(old_image_path)
        
        return jsonify({
            'success': True,
            'image_path': filename
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Add this route to serve profile images
@app.route('/static/profile_images/<filename>')
def serve_profile_image(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/toggle_user_status/<user_id>', methods=['POST'])
@csrf.exempt  # Add this if you're using AJAX
def toggle_user_status(user_id):
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        user = users.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        current_status = user.get('profile_status', 'active')
        new_status = 'inactive' if current_status == 'active' else 'active'
        
        result = users.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {
                'profile_status': new_status,
                'updated_at': datetime.now()
            }}
        )
        
        if result.modified_count == 0:
            return jsonify({'error': 'Failed to update status'}), 500
        
        log_activity(
            'User Status Update',
            f"User {user['username']} status changed to {new_status}"
        )
        
        return jsonify({
            'success': True,
            'new_status': new_status,
            'message': f'User status updated to {new_status}'
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/view_user/<user_id>')
def view_user(user_id):
    if 'username' not in session:
        flash('Please log in first!', 'danger')
        return redirect(url_for('login'))
        
    try:
        # Get user details
        user = users.find_one({'_id': ObjectId(user_id)})
        if not user:
            flash('User not found!', 'danger')
            return redirect(url_for('manage_users'))
            
        # Add created_at if it doesn't exist
        if 'created_at' not in user:
            user['created_at'] = user.get('timestamp', datetime.now())
        
        # Get user's activities
        user_activities = list(activities.find(
            {'username': user['username']},
            {'_id': 0}
        ).sort('timestamp', -1).limit(50))
        
        # Get user's applications
        user_apps = list(applications.find(
            {'submitted_by': user['username']},
            {'_id': 1, 'business_name': 1, 'status': 1, 'timestamp': 1}
        ).sort('timestamp', -1))
        
        # Convert ObjectId to string for applications
        for app in user_apps:
            app['_id'] = str(app['_id'])
            if 'timestamp' in app:
                app['created_at'] = app['timestamp']
                
        # Convert ObjectId to string for user
        user['_id'] = str(user['_id'])
        
        return render_template('view_user.html', 
                             user=user,
                             activities=user_activities,
                             applications=user_apps)
                             
    except Exception as e:
        print(f"Error in view_user: {str(e)}")
        flash('Error loading user details!', 'danger')
        return redirect(url_for('manage_users'))

@app.route('/export_users')
def export_users():
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        # Get all users excluding passwords
        all_users = list(users.find({}, {'password': 0}))
        
        # Create a BytesIO object
        si = StringIO()
        writer = csv.writer(si)
        
        # Write headers
        headers = ['ID', 'Username', 'Name', 'Email', 'Role', 'Status', 'Is Expert']
        writer.writerow(headers)
        
        # Write user data
        for user in all_users:
            writer.writerow([
                str(user['_id']),
                user.get('username', ''),
                user.get('name', ''),
                user.get('email', ''),
                user.get('role', ''),
                user.get('profile_status', 'inactive'),
                'Yes' if user.get('is_expert', False) else 'No'
            ])
        
        # Create the response
        output = make_response(si.getvalue())
        output.headers["Content-Disposition"] = "attachment; filename=users_export.csv"
        output.headers["Content-type"] = "text/csv"
        
        # Log the export
        log_activity('User Export', f"Users exported by {session['username']}")
        
        return output

    except Exception as e:
        print(f"Export error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Add these configurations
app.config['CSRF_ENABLED'] = True
app.config['WTF_CSRF_CHECK_DEFAULT'] = False  # Disable CSRF check for specific routes if needed

# Add these routes to handle settings
@app.route('/settings')
def settings():
    if 'username' not in session:
        flash('Please login to access settings', 'error')
        return redirect(url_for('login'))
    return render_template('settings.html')

@app.route('/update_profile_settings', methods=['POST'])
def update_profile_settings():
    if 'username' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    try:
        email_notifications = request.form.get('email_notifications') == 'on'
        language = request.form.get('language')
        
        # Update user settings in database
        users.update_one(
            {'username': session['username']},
            {'$set': {
                'settings.email_notifications': email_notifications,
                'settings.language': language
            }}
        )
        
        flash('Settings updated successfully', 'success')
        return redirect(url_for('settings'))
    except Exception as e:
        flash('Error updating settings', 'error')
        return redirect(url_for('settings'))

@app.route('/update_security_settings', methods=['POST'])
def update_security_settings():
    if 'username' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    try:
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Get user from database
        user = users.find_one({'username': session['username']})
        
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('settings'))
        
        # Verify current password
        if not bcrypt.checkpw(current_password.encode('utf-8'), user['password']):
            flash('Current password is incorrect', 'error')
            return redirect(url_for('settings'))
        
        # Verify new password matches confirmation
        if new_password != confirm_password:
            flash('New passwords do not match', 'error')
            return redirect(url_for('settings'))
        
        # Hash and update new password
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        users.update_one(
            {'username': session['username']},
            {'$set': {'password': hashed_password}}
        )
        
        flash('Password updated successfully', 'success')
        return redirect(url_for('settings'))
    except Exception as e:
        flash('Error updating password', 'error')
        return redirect(url_for('settings'))

# Analytics Routes
@app.route('/reports')
def page_analytics():
    if 'username' not in session:
        flash('Please log in to access analytics', 'error')
        return redirect(url_for('login'))
    
    # Fetch analytics data
    total_applications = applications.count_documents({})
    approved_applications = applications.count_documents({'status': 'approved'})
    pending_applications = applications.count_documents({'status': 'pending'})
    rejected_applications = applications.count_documents({'status': 'rejected'})
    
    # User activity analytics
    recent_activities = list(activities.find().sort('timestamp', -1).limit(10))
    
    return render_template('analytics/page_analytics.html', 
                           total_applications=total_applications,
                           approved_applications=approved_applications,
                           pending_applications=pending_applications,
                           rejected_applications=rejected_applications,
                           recent_activities=recent_activities)

@app.route('/detailed_reports')
def detailed_reports():
    if 'username' not in session:
        flash('Please log in to access detailed reports', 'error')
        return redirect(url_for('login'))
    
    # Fetch detailed reports data
    all_reports = list(reports.find().sort('timestamp', -1))
    
    # Aggregate reports by type and status
    report_types = reports.aggregate([
        {'$group': {
            '_id': '$type',
            'count': {'$sum': 1}
        }}
    ])
    
    return render_template('analytics/detailed_reports.html', 
                           reports=all_reports,
                           report_types=list(report_types))

@app.route('/performance')
def performance_metrics():
    if 'username' not in session:
        flash('Please log in to access performance metrics', 'error')
        return redirect(url_for('login'))
    
    # Performance metrics
    application_processing_times = list(applications.aggregate([
        {'$group': {
            '_id': '$status',
            'avg_processing_time': {'$avg': {'$subtract': ['$processed_date', '$timestamp']}}
        }}
    ]))
    
    # User performance metrics
    user_application_counts = list(applications.aggregate([
        {'$group': {
            '_id': '$submitted_by',
            'total_applications': {'$sum': 1},
            'approved_applications': {'$sum': {'$cond': [{'$eq': ['$status', 'approved']}, 1, 0]}}
        }}
    ]))
    
    return render_template('analytics/performance_metrics.html', 
                           processing_times=application_processing_times,
                           user_performance=user_application_counts)

@app.route('/export_page_analytics')
def export_page_analytics():
    if 'username' not in session:
        flash('Please log in to export analytics', 'error')
        return redirect(url_for('login'))
    
    # Fetch analytics data
    total_applications = applications.count_documents({})
    approved_applications = applications.count_documents({'status': 'approved'})
    pending_applications = applications.count_documents({'status': 'pending'})
    rejected_applications = applications.count_documents({'status': 'rejected'})
    
    # Create CSV
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['Metric', 'Count'])
    writer.writerow(['Total Applications', total_applications])
    writer.writerow(['Approved Applications', approved_applications])
    writer.writerow(['Pending Applications', pending_applications])
    writer.writerow(['Rejected Applications', rejected_applications])
    
    # Create the response
    output = make_response(output.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=page_analytics_export.csv"
    output.headers["Content-type"] = "text/csv"
    
    # Log the export
    log_activity('Page Analytics Export', f"Page analytics exported by {session['username']}")
    
    return output

@app.route('/export_performance_metrics/<format>')
def export_performance_metrics(format):
    if session.get('role') != 'admin':
        flash('Access denied!', 'danger')
        return redirect(url_for('login'))

    try:
        # Get performance metrics data
        application_processing_times = list(applications.aggregate([
            {'$group': {
                '_id': '$status',
                'avg_processing_time': {'$avg': {'$subtract': ['$processed_date', '$timestamp']}}
            }}
        ]))
        
        # User performance metrics
        user_performance = list(applications.aggregate([
            {'$group': {
                '_id': '$submitted_by',
                'total_applications': {'$sum': 1},
                'approved_applications': {'$sum': {'$cond': [{'$eq': ['$status', 'approved']}, 1, 0]}}
            }}
        ]))

        if format == 'csv':
            # Create CSV in memory using BytesIO
            output = BytesIO()
            writer = csv.writer(TextIOWrapper(output, 'utf-8'))
            
            # Write processing times
            writer.writerow(['Processing Times by Status'])
            writer.writerow(['Status', 'Average Processing Time (Hours)'])
            for time in application_processing_times:
                writer.writerow([
                    time['_id'],
                    f"{(time.get('avg_processing_time', 0) / 3600000):.2f}"
                ])
            
            writer.writerow([])  # Empty row for separation
            
            # Write user performance
            writer.writerow(['User Performance Metrics'])
            writer.writerow(['User', 'Total Applications', 'Approved Applications', 'Success Rate'])
            for user in user_performance:
                total = user['total_applications']
                approved = user['approved_applications']
                success_rate = (approved / total * 100) if total > 0 else 0
                writer.writerow([
                    user['_id'],
                    total,
                    approved,
                    f"{success_rate:.2f}%"
                ])
            
            output.seek(0)
            return send_file(
                output,
                mimetype='text/csv',
                as_attachment=True,
                download_name='performance_metrics.csv'
            )

        elif format == 'pdf':
            buffer = BytesIO()
            doc = SimpleDocTemplate(
                buffer,
                pagesize=letter,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=72
            )

            # Define styles
            styles = getSampleStyleSheet()
            styles.add(ParagraphStyle(
                name='CustomTitle',
                fontName='Helvetica-Bold',
                fontSize=20,
                spaceAfter=30,
                alignment=1
            ))

            # Create document elements
            elements = []

            # Add title
            elements.append(Paragraph("Performance Metrics Report", styles['CustomTitle']))
            elements.append(Spacer(1, 20))

            # Add processing times table
            elements.append(Paragraph("Processing Times by Status", styles['Heading1']))
            elements.append(Spacer(1, 12))
            
            pt_data = [['Status', 'Average Processing Time (Hours)']]
            for time in application_processing_times:
                pt_data.append([
                    time['_id'],
                    f"{(time.get('avg_processing_time', 0) / 3600000):.2f}"
                ])
            
            pt_table = Table(pt_data)
            pt_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(pt_table)
            elements.append(Spacer(1, 20))

            # Add user performance table
            elements.append(Paragraph("User Performance Metrics", styles['Heading1']))
            elements.append(Spacer(1, 12))
            
            up_data = [['User', 'Total Applications', 'Approved', 'Success Rate']]
            for user in user_performance:
                total = user['total_applications']
                approved = user['approved_applications']
                success_rate = (approved / total * 100) if total > 0 else 0
                up_data.append([
                    user['_id'],
                    str(total),
                    str(approved),
                    f"{success_rate:.2f}%"
                ])
            
            up_table = Table(up_data)
            up_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(up_table)

            # Build PDF
            doc.build(elements)
            buffer.seek(0)
            
            return send_file(
                buffer,
                mimetype='application/pdf',
                as_attachment=True,
                download_name='performance_metrics.pdf'
            )

        else:
            flash('Invalid export format!', 'danger')
            return redirect(url_for('performance_metrics'))

    except Exception as e:
        print(f"Export error: {str(e)}")
        flash('Error exporting data!', 'danger')
        return redirect(url_for('performance_metrics'))

@app.route('/api/admin/profile')
def get_admin_profile():
    if 'username' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    
    try:
        user = users.find_one({'username': session['username']})
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404
            
        return jsonify({
            'success': True,
            'name': user.get('name', ''),
            'email': user.get('email', ''),
            'phone': user.get('phone', ''),
            'profile_image': user.get('profile_image', 'default-profile.png')
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/inspections', methods=['GET', 'POST'])
def manage_inspections():
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        if request.method == 'POST':
            data = request.get_json()
            
            # Validate required fields
            required_fields = ['business_id', 'business_name', 'inspector_id', 'inspector_name', 'date', 'time']
            if not all(data.get(field) for field in required_fields):
                return jsonify({
                    'success': False,
                    'error': 'Missing required fields'
                }), 400

            inspection_data = {
                'business_id': data['business_id'],
                'business_name': data['business_name'],
                'inspector_id': data['inspector_id'],
                'inspector_name': data['inspector_name'],
                'date': data['date'],
                'time': data['time'],
                'location': data.get('location', ''),
                'status': 'scheduled',
                'notes': data.get('notes', ''),
                'created_by': session.get('username'),
                'created_at': datetime.now()
            }
            
            # Insert inspection record
            result = inspections.insert_one(inspection_data)
            
            # Send email notification to inspector
            email_sent = send_inspection_notification_email(
                data['inspector_id'],
                inspection_data
            )

            response_data = {
                'success': True,
                'message': 'Inspection scheduled successfully',
                'inspection_id': str(result.inserted_id),
                'email_sent': email_sent
            }

            if not email_sent:
                response_data['warning'] = 'Inspection scheduled but email notification failed'

            # Emit socket event for real-time updates
            socketio.emit('new_inspection', {
                'message': 'New inspection scheduled',
                'inspection_id': str(result.inserted_id)
            })

            return jsonify(response_data)

        # GET method
        pipeline = [
            {
                '$lookup': {
                    'from': 'applications',
                    'localField': 'business_id',
                    'foreignField': '_id',
                    'as': 'business_info'
                }
            },
            {
                '$lookup': {
                    'from': 'users',
                    'localField': 'inspector_id',
                    'foreignField': '_id',
                    'as': 'inspector_info'
                }
            }
        ]
        
        inspection_list = list(inspections.find())
        
        formatted_inspections = []
        for inspection in inspection_list:
            formatted_inspection = {
                '_id': str(inspection['_id']),
                'business_name': inspection.get('business_name', ''),
                'inspector_name': inspection.get('inspector_name', ''),
                'date': inspection.get('date', ''),
                'time': inspection.get('time', ''),
                'location': inspection.get('location', ''),
                'status': inspection.get('status', 'pending'),
                'notes': inspection.get('notes', ''),
                'created_at': inspection['created_at'].isoformat() if 'created_at' in inspection else ''
            }
            formatted_inspections.append(formatted_inspection)

        return jsonify({
            'success': True,
            'inspections': formatted_inspections
        })

    except Exception as e:
        print(f"Error in manage_inspections: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/schedule-inspection-data')
def get_inspection_scheduling_data():
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        # Get approved businesses
        businesses = list(applications.find(
            {'status': 'approved'},
            {'_id': 1, 'business_name': 1, 'business_address': 1}
        ))

        # Get inspectors (users with inspector role)
        inspectors = list(users.find(
            {'role': 'inspector'},
            {'_id': 1, 'name': 1, 'email': 1}
        ))

        return jsonify({
            'success': True,
            'businesses': [{
                'id': str(b['_id']),
                'name': b['business_name'],
                'address': b.get('business_address', '')
            } for b in businesses],
            'inspectors': [{
                'id': str(i['_id']),
                'name': i.get('name', 'Unknown'),
                'email': i.get('email', '')
            } for i in inspectors]
        })

    except Exception as e:
        print(f"Error in get_inspection_scheduling_data: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/inspection/<inspection_id>', methods=['GET', 'PUT'])
def inspection_details(inspection_id):
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        if request.method == 'GET':
            inspection = db.inspections.find_one({'_id': ObjectId(inspection_id)})
            if not inspection:
                return jsonify({'error': 'Inspection not found'}), 404

            inspection['_id'] = str(inspection['_id'])
            inspection['created_at'] = inspection['created_at'].isoformat()

            return jsonify({
                'success': True,
                'inspection': inspection
            })

        elif request.method == 'PUT':
            data = request.get_json()
            update_data = {
                'status': data.get('status'),
                'notes': data.get('notes'),
                'updated_by': session.get('username'),
                'updated_at': datetime.now()
            }

            result = db.inspections.update_one(
                {'_id': ObjectId(inspection_id)},
                {'$set': update_data}
            )

            if result.modified_count == 0:
                return jsonify({'error': 'Inspection not found'}), 404

            return jsonify({
                'success': True,
                'message': 'Inspection updated successfully'
            })

    except Exception as e:
        print(f"Error in inspection_details: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/inspection/<inspection_id>/complete', methods=['POST'])
def complete_inspection():
    try:
        data = request.get_json()
        inspection_id = data.get('inspection_id')
        report_data = data.get('report_data')
        
        # Get inspection details
        inspection = inspections.find_one({'_id': ObjectId(inspection_id)})
        if not inspection:
            return jsonify({'error': 'Inspection not found'}), 404

        # Get business and inspector details
        business = applications.find_one({'_id': ObjectId(inspection['business_id'])})
        inspector = users.find_one({'_id': ObjectId(inspection['inspector_id'])})

        # Generate PDF report first
        try:
            report_path = generate_detailed_inspection_report(inspection, business, inspector, report_data)
            
            # Update inspection status only if report generation is successful
            if report_path:
                report_url = f"/download-inspection-report/{inspection_id}"
                
                inspections.update_one(
                    {'_id': ObjectId(inspection_id)},
                    {
                        '$set': {
                            'status': 'completed',
                            'completion_date': datetime.now(),
                            'report_data': report_data,
                            'completed_by': session.get('username'),
                            'report_generated': True,
                            'report_url': report_url,
                            'report_path': report_path
                        }
                    }
                )

                # Send email to business owner with report
                try:
                    with open(report_path, 'rb') as report_file:
                        business_subject = "Fire Safety Inspection Report"
                        business_body = f"""
Dear {business.get('contact_person', 'Business Owner')},

The fire safety inspection for your business has been completed.

Business Details:
- Name: {business['business_name']}
- Address: {business['business_address']}

Inspection Details:
- Date: {inspection['date']}
- Time: {datetime.now().strftime('%H:%M')}
- Inspector: {inspector['name']}

You can view and download the inspection report from your dashboard.

Best regards,
Fire Safety Department
"""
                        send_email_with_attachment(
                            business_subject,
                            business['email'],
                            business_body,
                            report_file,
                            f"inspection_report_{inspection_id}.pdf"
                        )

                except Exception as e:
                    print(f"Error sending email: {str(e)}")

                return jsonify({
                    'success': True,
                    'message': 'Inspection completed and report sent successfully',
                    'report_url': report_url
                })
            else:
                return jsonify({'error': 'Failed to generate report'}), 500

        except Exception as e:
            print(f"Error generating report: {str(e)}")
            return jsonify({'error': 'Failed to generate inspection report'}), 500

    except Exception as e:
        print(f"Error completing inspection: {str(e)}")
        return jsonify({'error': str(e)}), 500

def generate_detailed_inspection_report(inspection, business, inspector, report_data):
    try:
        # Create reports directory if it doesn't exist
        os.makedirs('static/reports', exist_ok=True)
        report_path = f"static/reports/inspection_{str(inspection['_id'])}.pdf"

        # Generate PDF
        doc = SimpleDocTemplate(
            report_path,
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72
        )

        # Define styles
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(
            name='CustomTitle',
            fontName='Helvetica-Bold',
            fontSize=20,
            spaceAfter=30,
            alignment=1
        ))

        # Create document elements
        elements = []

        # Add title
        elements.append(Paragraph("FIRE SAFETY INSPECTION REPORT", styles['CustomTitle']))
        elements.append(Spacer(1, 20))

        # Add inspection details
        inspection_data = [
            ['Inspection ID:', str(inspection['_id'])],
            ['Date:', inspection['date']],
            ['Time:', inspection['time']],
            ['Status:', 'Completed'],
            ['Completion Date:', datetime.now().strftime('%Y-%m-%d %H:%M')]
        ]

        # Add business information
        business_data = [
            ['Business Name:', business['business_name']],
            ['Address:', business['business_address']],
            ['Contact Person:', business.get('contact_person', 'N/A')],
            ['Contact Email:', business.get('email', 'N/A')],
            ['Contact Phone:', business.get('contact_number', 'N/A')]
        ]

        # Add inspector information
        inspector_data = [
            ['Inspector Name:', inspector['name']],
            ['Inspector ID:', str(inspector['_id'])],
            ['Inspector Email:', inspector.get('email', 'N/A')]
        ]

        # Add findings
        safety_findings = []
        for category, items in report_data.items():
            if isinstance(items, dict):
                for item, details in items.items():
                    if isinstance(details, dict):
                        status = details.get('status', 'N/A')
                        notes = details.get('notes', '')
                        safety_findings.append([category, item, status, notes])
                    else:
                        safety_findings.append([category, item, str(details), ''])

        # Create tables
        tables_data = [
            ('Inspection Details', inspection_data),
            ('Business Information', business_data),
            ('Inspector Information', inspector_data),
            ('Safety Inspection Findings', safety_findings)
        ]

        for title, data in tables_data:
            elements.append(Paragraph(title, styles['Heading1']))
            elements.append(Spacer(1, 12))
            
            if title == 'Safety Inspection Findings':
                t = Table(data, colWidths=[100, 150, 100, 150])
                t.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 12),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
            else:
                t = Table(data, colWidths=[150, 350])
                t.setStyle(TableStyle([
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
            
            elements.append(t)
            elements.append(Spacer(1, 20))

        # Add signature section
        signature_data = [
            ['_____________________', '_____________________'],
            ['Inspector Signature', 'Date'],
            [inspector['name'], datetime.now().strftime('%Y-%m-%d')]
        ]
        
        signature_table = Table(signature_data, colWidths=[250, 250])
        signature_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 1), (-1, 1), 'Helvetica-Bold')
        ]))
        elements.append(signature_table)

        # Build PDF
        doc.build(elements)
        return report_path

    except Exception as e:
        print(f"Error generating detailed report: {str(e)}")
        raise

def send_email_with_attachment(subject, recipient, body, attachment, filename):
    try:
        msg = Message(
            subject,
            sender=app.config['MAIL_USERNAME'],
            recipients=[recipient]
        )
        msg.body = body
        
        # Attach the PDF report
        msg.attach(
            filename=filename,
            content_type='application/pdf',
            data=attachment.read()
        )
        
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending email with attachment: {str(e)}")
        return False

@app.route('/download-inspection-report/<inspection_id>')
def download_inspection_report(inspection_id):
    try:
        inspection = inspections.find_one({'_id': ObjectId(inspection_id)})
        if not inspection or 'report_path' not in inspection:
            return jsonify({'error': 'Report not found'}), 404

        report_path = inspection['report_path']
        if not os.path.exists(report_path):
            return jsonify({'error': 'Report file not found'}), 404

        return send_file(
            report_path,
            as_attachment=True,
            download_name=f"inspection_report_{inspection_id}.pdf"
        )

    except Exception as e:
        print(f"Error downloading report: {str(e)}")
        return jsonify({'error': 'Failed to download report'}), 500

def generate_inspection_report(inspection_id):
    try:
        inspection = inspections.find_one({'_id': ObjectId(inspection_id)})
        business = applications.find_one({'_id': ObjectId(inspection['business_id'])})
        inspector = users.find_one({'_id': ObjectId(inspection['inspector_id'])})
        
        # Generate HTML for the report
        html_content = f"""
            <html>
                <head>
                    <style>
                        body {{ font-family: Arial, sans-serif; }}
                        .header {{ text-align: center; margin-bottom: 30px; }}
                        .section {{ margin-bottom: 20px; }}
                        .table {{ width: 100%; border-collapse: collapse; }}
                        .table td, .table th {{ border: 1px solid #ddd; padding: 8px; }}
                    </style>
                </head>
                <body>
                    <div class="header">
                        <h1>Fire Safety Inspection Report</h1>
                        <p>Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    </div>
                    
                    <div class="section">
                        <h2>Business Information</h2>
                        <table class="table">
                            <tr><th>Business Name</th><td>{business['business_name']}</td></tr>
                            <tr><th>Address</th><td>{business['business_address']}</td></tr>
                            <tr><th>Contact Person</th><td>{business.get('contact_person', 'N/A')}</td></tr>
                            <tr><th>Contact Email</th><td>{business.get('email', 'N/A')}</td></tr>
                        </table>
                    </div>
                    
                    <div class="section">
                        <h2>Inspection Details</h2>
                        <table class="table">
                            <tr><th>Inspection Date</th><td>{inspection['date']}</td></tr>
                            <tr><th>Inspector Name</th><td>{inspector['name']}</td></tr>
                            <tr><th>Status</th><td>{inspection['status']}</td></tr>
                        </table>
                    </div>
                    
                    <div class="section">
                        <h2>Inspection Findings</h2>
                        <table class="table">
                            {generate_findings_html(inspection.get('report_data', {}))}
                        </table>
                    </div>
                </body>
            </html>
        """
        
        # Create reports directory if it doesn't exist
        os.makedirs('static/reports', exist_ok=True)
        
        # Generate PDF
        report_path = f"static/reports/inspection_{inspection_id}.pdf"
        pdfkit.from_string(html_content, report_path)
        
        return report_path
        
    except Exception as e:
        print(f"Error generating report: {str(e)}")
        raise

def generate_findings_html(report_data):
    html = ""
    for category, items in report_data.items():
        html += f"<tr><th colspan='2'>{category}</th></tr>"
        for item, status in items.items():
            html += f"<tr><td>{item}</td><td>{status}</td></tr>"
    return html

def send_inspection_email(inspector_email, inspection, business, report_path):
    try:
        msg = Message(
            'New Inspection Assignment',
            sender=app.config['MAIL_USERNAME'],
            recipients=[inspector_email]
        )
        
        msg.body = f"""
            Dear {inspection['inspector_name']},

            You have been assigned a new fire safety inspection:

            Business: {business['business_name']}
            Address: {business['business_address']}
            Date: {inspection['date']}
            Time: {inspection['time']}
            Location: {inspection.get('location', 'As per business address')}

            Contact Person: {business.get('contact_person', 'N/A')}
            Contact Email: {business.get('email', 'N/A')}
            Contact Phone: {business.get('contact_number', 'N/A')}

            Please review the attached inspection report and complete the inspection as scheduled.

            Best regards,
            Fire Department
        """
        
        with app.open_resource(report_path) as fp:
            msg.attach(
                f"inspection_report_{inspection['_id']}.pdf",
                'application/pdf',
                fp.read()
            )
            
        mail.send(msg)
        return True
        
    except Exception as e:
        print(f"Error sending email: {str(e)}")
        return False

def send_inspection_notification_email(inspector_id, inspection_data):
    """Send email notifications to both inspector and business owner"""
    try:
        # Get inspector details
        inspector = users.find_one({'_id': ObjectId(inspector_id)})
        if not inspector or 'email' not in inspector:
            print(f"Inspector not found or no email for ID: {inspector_id}")
            return False

        # Get business details
        business = applications.find_one({'_id': ObjectId(inspection_data['business_id'])})
        if not business:
            print(f"Business not found for ID: {inspection_data['business_id']}")
            return False

        # Generate activation token
        activation_token = secrets.token_urlsafe(32)
        
        # Save token to inspection record
        inspections.update_one(
            {'_id': inspection_data['_id']},
            {'$set': {
                'activation_token': activation_token,
                'activated': False
            }}
        )

        # Generate activation link
        activation_link = f"{request.host_url}activate_inspection/{str(inspection_data['_id'])}/{activation_token}"

        # Send email to inspector
        inspector_subject = "New Fire Safety Inspection Assignment - Action Required"
        inspector_body = f"""
Dear {inspector['name']},

You have been assigned a new fire safety inspection:

Business Details:
- Name: {business['business_name']}
- Address: {business['business_address']}
- Contact Person: {business.get('contact_person', 'N/A')}
- Contact Number: {business.get('contact_number', 'N/A')}

Inspection Schedule:
- Date: {inspection_data['date']}
- Time: {inspection_data['time']}
- Location: {inspection_data.get('location', 'As per business address')}

Click the following link to activate and start the inspection:
{activation_link}

Please note: Activate the inspection only when you arrive at the location.

Best regards,
Fire Safety Department
"""
        send_email(inspector_subject, inspector['email'], inspector_body)

        # Send email to business owner
        business_subject = "Upcoming Fire Safety Inspection Scheduled"
        business_body = f"""
Dear {business.get('contact_person', 'Business Owner')},

A fire safety inspection has been scheduled for your business:

Inspection Details:
- Date: {inspection_data['date']}
- Time: {inspection_data['time']}
- Inspector: {inspector['name']}

Business Information:
- Name: {business['business_name']}
- Address: {business['business_address']}

Please ensure:
1. A responsible person is present during the inspection
2. All safety equipment is accessible
3. Relevant documentation is ready
4. Access to all areas is available

You will receive another notification when the inspector arrives and begins the inspection.

Best regards,
Fire Safety Department
"""
        send_email(business_subject, business['email'], business_body)

        return True

    except Exception as e:
        print(f"Error sending inspection notification emails: {str(e)}")
        return False

@app.route('/inspection_dashboard')
def inspection_dashboard():
    if 'username' not in session or session.get('role') != 'admin':
        flash('Access denied!', 'danger')
        return redirect(url_for('login'))
    
    return render_template('inspection_dashboard.html')

@app.route('/api/inspections/overview')
def get_inspection_overview():
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        # Get inspection stats
        today = datetime.now().strftime('%Y-%m-%d')
        stats = {
            'pending': inspections.count_documents({'status': 'pending'}),
            'completed': inspections.count_documents({'status': 'completed'}),
            'today': inspections.count_documents({'date': today}),
            'total': inspections.count_documents({})
        }
        
        # Get recent inspections
        recent = list(inspections.find().sort('date', -1).limit(5))
        for inspection in recent:
            inspection['_id'] = str(inspection['_id'])
            if 'created_at' in inspection:
                inspection['created_at'] = inspection['created_at'].isoformat()
        
        return jsonify({
            'success': True,
            'stats': stats,
            'recent': recent
        })
        
    except Exception as e:
        print(f"Error in get_inspection_overview: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/inspections/scheduled')
def get_scheduled_inspections():
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        date_filter = request.args.get('date')
        query = {'status': 'scheduled'}
        
        if date_filter:
            query['date'] = date_filter
        
        scheduled = list(inspections.find(query).sort('date', 1))
        for inspection in scheduled:
            inspection['_id'] = str(inspection['_id'])
        
        return jsonify({
            'success': True,
            'inspections': scheduled
        })
        
    except Exception as e:
        print(f"Error in get_scheduled_inspections: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/inspections/completed')
def get_completed_inspections():
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        month_filter = request.args.get('month')  # Format: YYYY-MM
        query = {'status': 'completed'}
        
        if month_filter:
            start_date = f"{month_filter}-01"
            year, month = map(int, month_filter.split('-'))
            if month == 12:
                next_year = year + 1
                next_month = 1
            else:
                next_year = year
                next_month = month + 1
            end_date = f"{next_year}-{next_month:02d}-01"
            
            query['date'] = {
                '$gte': start_date,
                '$lt': end_date
            }
        
        completed = list(inspections.find(query).sort('date', -1))
        for inspection in completed:
            inspection['_id'] = str(inspection['_id'])
        
        return jsonify({
            'success': True,
            'inspections': completed
        })
        
    except Exception as e:
        print(f"Error in get_completed_inspections: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/inspections/reports')
def get_inspection_reports():
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        reports = list(inspections.find(
            {'status': 'completed', 'report_generated': True}
        ).sort('date', -1))
        
        for report in reports:
            report['_id'] = str(report['_id'])
            if 'completion_date' in report:
                report['completion_date'] = report['completion_date'].isoformat()
        
        return jsonify({
            'success': True,
            'reports': reports
        })
        
    except Exception as e:
        print(f"Error in get_inspection_reports: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/detailed-inspection-reports')
def get_detailed_inspection_reports():
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        # Get all completed inspections with reports
        reports = list(inspections.find({
            'status': 'completed',
            'report_generated': True
        }).sort('completion_date', -1))

        # Format the reports data
        formatted_reports = []
        for report in reports:
            business = applications.find_one({'_id': ObjectId(report['business_id'])})
            inspector = users.find_one({'_id': ObjectId(report['inspector_id'])})
            
            formatted_reports.append({
                '_id': str(report['_id']),
                'date': report.get('date'),
                'business_name': business.get('business_name', 'N/A'),
                'inspector_name': inspector.get('name', 'N/A'),
                'status': report.get('status'),
                'completion_date': report.get('completion_date'),
                'report_url': f"/download-inspection-report/{str(report['_id'])}",
                'findings': report.get('report_data', {})
            })

        return jsonify({
            'success': True,
            'reports': formatted_reports
        })

    except Exception as e:
        print(f"Error fetching inspection reports: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/inspection-reports')
def inspection_reports():
    if session.get('role') != 'admin':
        flash('Access denied!', 'danger')
        return redirect(url_for('login'))
    
    try:
        # Get all completed inspections with reports
        reports = list(inspections.find({
            'status': 'completed',
            'report_generated': True
        }).sort('completion_date', -1))

        # Format report data for template
        formatted_reports = []
        for report in reports:
            business = applications.find_one({'_id': ObjectId(report['business_id'])})
            inspector = users.find_one({'_id': ObjectId(report['inspector_id'])})
            
            formatted_report = {
                '_id': str(report['_id']),
                'date': report.get('date'),
                'business_name': business.get('business_name', 'N/A'),
                'inspector_name': inspector.get('name', 'N/A'),
                'status': report.get('status'),
                'completion_date': report.get('completion_date'),
                'report_url': f"/download-inspection-report/{str(report['_id'])}",
                'findings': report.get('report_data', {})
            }
            formatted_reports.append(formatted_report)

        return render_template('inspection_reports.html', reports=formatted_reports)

    except Exception as e:
        print(f"Error loading inspection reports: {str(e)}")
        flash('Error loading inspection reports', 'danger')
        return redirect(url_for('admin_dashboard'))

@app.route('/view_license/<license_id>')
def view_license(license_id):
    if 'username' not in session:
        flash('Please log in first!', 'danger')
        return redirect(url_for('login'))
    
    try:
        license = licenses.find_one({'_id': ObjectId(license_id)})
        if not license:
            flash('License not found!', 'danger')
            return redirect(url_for('manage_licenses'))
        
        # Add created_at if it doesn't exist
        if 'created_at' not in license:
            license['created_at'] = license.get('issue_date', datetime.now())
        
        # Convert ObjectId to string
        license['_id'] = str(license['_id'])
        
        return render_template('view_license.html', license=license)
        
    except Exception as e:
        print(f"Error in view_license: {str(e)}")
        flash('Error loading license!', 'danger')
        return redirect(url_for('manage_licenses'))

@app.route('/manage_licenses')
def manage_licenses():
    if 'username' not in session:
        flash('Please log in first!', 'danger')
        return redirect(url_for('login'))
    
    all_licenses = list(licenses.find().sort('issue_date', -1))
    return render_template('manage_licenses.html', licenses=all_licenses)

@app.route('/api/licenses', methods=['GET'])
def get_licenses():
    if session.get('role') not in ['admin', 'user']:
        return jsonify({'error': 'Unauthorized'}), 401
        
    try:
        if session['role'] == 'admin':
            # Admin sees all licenses
            license_list = list(licenses.find())
        else:
            # Users see only their licenses
            applications = list(db.applications.find({'username': session['username']}))
            app_ids = [str(app['_id']) for app in applications]
            license_list = list(licenses.find({'application_id': {'$in': app_ids}}))
        
        # Convert ObjectId to string
        for license in license_list:
            license['_id'] = str(license['_id'])
            license['issue_date'] = license['issue_date'].strftime('%Y-%m-%d')
            license['expiry_date'] = license['expiry_date'].strftime('%Y-%m-%d')
        
        return jsonify({'licenses': license_list})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/license/<license_id>/renew', methods=['POST'])
def renew_license(license_id):
    if session.get('role') not in ['admin', 'user']:
        return jsonify({'error': 'Unauthorized'}), 401
        
    try:
        license_doc = licenses.find_one({'_id': ObjectId(license_id)})
        if not license_doc:
            return jsonify({'error': 'License not found'}), 404
            
        # Calculate new expiry date
        new_expiry = datetime.now() + timedelta(days=365)
        
        # Add renewal record
        renewal = {
            'renewal_date': datetime.now(),
            'previous_expiry': license_doc['expiry_date'],
            'new_expiry': new_expiry,
            'renewed_by': session.get('username')
        }
        
        # Update license
        licenses.update_one(
            {'_id': ObjectId(license_id)},
            {
                '$set': {
                    'expiry_date': new_expiry,
                    'status': 'active'
                },
                '$push': {
                    'renewals': renewal
                }
            }
        )
        
        return jsonify({
            'success': True,
            'message': 'License renewed successfully',
            'new_expiry': new_expiry.strftime('%Y-%m-%d')
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def generate_license_number():
    """Generate a unique license number"""
    current_year = datetime.now().year
    # Get count of licenses in current year
    count = licenses.count_documents({
        'issue_date': {
            '$gte': datetime(current_year, 1, 1),
            '$lt': datetime(current_year + 1, 1, 1)
        }
    })
    # Format: FIRE-YYYY-XXXXX (where XXXXX is a 5-digit number)
    return f"FIRE-{current_year}-{(count + 1):05d}"

def create_license(application_id, business_data):
    """Create a new license when NOC is approved"""
    try:
        # Generate license number
        license_number = generate_license_number()
        issue_date = datetime.now()
        expiry_date = issue_date + timedelta(days=365)  # Valid for 1 year
        
        license_data = {
            'license_number': license_number,
            'application_id': application_id,
            'business_name': business_data['business_name'],
            'business_address': business_data['business_address'],
            'owner_name': business_data.get('contact_person', 'N/A'),
            'contact_number': business_data.get('contact_number', 'N/A'),
            'email': business_data.get('email', 'N/A'),
            'issue_date': issue_date,
            'expiry_date': expiry_date,
            'status': 'active',
            'renewals': [],
            'created_at': datetime.now()
        }
        
        result = licenses.insert_one(license_data)
        return str(result.inserted_id)
    except Exception as e:
        print(f"Error creating license: {str(e)}")
        return None

def approve_application(application_id):
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        # Get application details
        application = applications.find_one({'_id': ObjectId(application_id)})
        if not application:
            return jsonify({'error': 'Application not found'}), 404

        # Update application status
        result = applications.update_one(
            {'_id': ObjectId(application_id)},
            {'$set': {
                'status': 'approved',
                'approved_by': session['username'],
                'approved_at': datetime.now(),
                'valid_until': datetime.now() + timedelta(days=365)
            }}
        )
        
        if result.modified_count == 0:
            return jsonify({'error': 'Failed to approve application'}), 500

        # Generate license
        license_id = create_license(str(application_id), application)
        if license_id:
            # Update application with license reference
            applications.update_one(
                {'_id': ObjectId(application_id)},
                {'$set': {'license_id': license_id}}
            )
            
            # Generate and send approval notification
            send_approval_notification(application, license_id)
            
            return jsonify({
                'success': True,
                'message': 'Application approved and license generated successfully'
            })
        else:
            return jsonify({'error': 'Failed to generate license'}), 500

    except Exception as e:
        print(f"Error in approve_application: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/users', methods=['GET'])
def get_users():
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
        
    try:
        # Get all users except admins
        user_list = list(users.find({'role': {'$ne': 'admin'}}, 
                                  {'password': 0}))  # Exclude password field
        
        # Convert ObjectId to string for JSON serialization
        for user in user_list:
            user['_id'] = str(user['_id'])
            
        return jsonify({'users': user_list})
    except Exception as e:
        print(f"Error fetching users: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/licenses/create', methods=['POST'])
def create_new_license():
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
        
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['userId', 'businessName', 'businessAddress', 
                         'contactPerson', 'contactNumber', 'email']
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400
            
        # Get user details
        user = users.find_one({'_id': ObjectId(data['userId'])})
        if not user:
            return jsonify({'error': 'User not found'}), 404
            
        # Generate license number
        license_number = generate_license_number()
        
        # Create license data
        license_data = {
            'license_number': license_number,
            'user_id': ObjectId(data['userId']),
            'business_name': data['businessName'],
            'business_address': data['businessAddress'],
            'owner_name': data['contactPerson'],
            'contact_number': data['contactNumber'],
            'email': data['email'],
            'issue_date': datetime.now(),
            'expiry_date': datetime.now() + timedelta(days=365),
            'status': 'active',
            'renewals': [],
            'created_at': datetime.now(),
            'created_by': session['username']
        }
        
        # Insert license
        result = licenses.insert_one(license_data)
        
        # Send email notification
        subject = "New Fire Safety License Generated"
        body = f"""
Dear {data['contactPerson']},

Your Fire Safety License has been generated successfully:

License Details:
- License Number: {license_number}
- Business Name: {data['businessName']}
- Issue Date: {license_data['issue_date'].strftime('%Y-%m-%d')}
- Expiry Date: {license_data['expiry_date'].strftime('%Y-%m-%d')}

Please keep this license number for future reference. You can view and download
your license certificate from your dashboard.

Best regards,
Fire Safety Department
"""
        send_email(subject, data['email'], body)
        
        return jsonify({
            'success': True,
            'message': 'License generated successfully',
            'license_id': str(result.inserted_id)
        })
        
    except Exception as e:
        print(f"Error creating license: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/download_license/<license_id>')
def download_license(license_id):
    if 'username' not in session:
        flash('Please log in first!', 'danger')
        return redirect(url_for('login'))
        
    try:
        license_data = licenses.find_one({'_id': ObjectId(license_id)})
        if not license_data:
            flash('License not found!', 'danger')
            return redirect(url_for('manage_licenses'))
            
        # Create PDF
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        elements = []
        
        # Title
        elements.append(Paragraph('FIRE SAFETY LICENSE', styles['Title']))
        elements.append(Spacer(1, 20))
        
        # License details
        elements.extend([
            Paragraph(f'License Number: {license_data["license_number"]}', styles['Normal']),
            Paragraph(f'Business Name: {license_data["business_name"]}', styles['Normal']),
            Paragraph(f'Business Address: {license_data["business_address"]}', styles['Normal']),
            Paragraph(f'Owner Name: {license_data["owner_name"]}', styles['Normal']),
            Paragraph(f'Contact Number: {license_data["contact_number"]}', styles['Normal']),
            Paragraph(f'Issue Date: {license_data["issue_date"].strftime("%Y-%m-%d")}', styles['Normal']),
            Paragraph(f'Expiry Date: {license_data["expiry_date"].strftime("%Y-%m-%d")}', styles['Normal']),
            Spacer(1, 20)
        ])
        
        # Terms and conditions
        elements.extend([
            Paragraph('Terms and Conditions:', styles['Heading2']),
            Paragraph('1. This license must be displayed prominently at the business premises.', styles['Normal']),
            Paragraph('2. Regular fire safety inspections must be conducted.', styles['Normal']),
            Paragraph('3. Fire safety equipment must be maintained as per regulations.', styles['Normal']),
            Paragraph('4. License must be renewed before expiry date.', styles['Normal']),
            Spacer(1, 30)
        ])
        
        # Signature
        elements.extend([
            Paragraph('Authorized Signature:', styles['Normal']),
            Spacer(1, 20),
            Paragraph('_______________________', styles['Normal']),
            Paragraph('Fire Safety Department', styles['Normal'])
        ])
        
        doc.build(elements)
        
        # Prepare response
        buffer.seek(0)
        response = make_response(buffer.getvalue())
        response.headers["Content-Disposition"] = f'attachment; filename=license_{license_data["license_number"]}.pdf'
        response.headers["Content-Type"] = "application/pdf"
        
        return response
        
    except Exception as e:
        print(f"Error downloading license: {str(e)}")
        flash('Error generating license PDF!', 'danger')
        return redirect(url_for('manage_licenses'))

@app.route('/export_licenses')
def export_licenses():
    if session.get('role') != 'admin':
        flash('Access denied!', 'danger')
        return redirect(url_for('login'))
        
    try:
        # Get all licenses
        all_licenses = list(licenses.find())
        
        # Create Excel file
        output = BytesIO()
        workbook = Workbook()
        sheet = workbook.active
        sheet.title = 'Licenses'
        
        # Headers
        headers = ['License Number', 'Business Name', 'Owner Name', 'Contact Number', 
                  'Email', 'Issue Date', 'Expiry Date', 'Status']
        for col, header in enumerate(headers, 1):
            sheet.cell(row=1, column=col, value=header)
        
        # Data
        for row, license in enumerate(all_licenses, 2):
            sheet.cell(row=row, column=1, value=license.get('license_number'))
            sheet.cell(row=row, column=2, value=license.get('business_name'))
            sheet.cell(row=row, column=3, value=license.get('owner_name'))
            sheet.cell(row=row, column=4, value=license.get('contact_number'))
            sheet.cell(row=row, column=5, value=license.get('email'))
            sheet.cell(row=row, column=6, value=license.get('issue_date').strftime('%Y-%m-%d'))
            sheet.cell(row=row, column=7, value=license.get('expiry_date').strftime('%Y-%m-%d'))
            sheet.cell(row=row, column=8, value='Active' if license.get('expiry_date') > datetime.now() else 'Expired')
        
        # Save to buffer
        workbook.save(output)
        output.seek(0)
        
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=f'licenses_export_{datetime.now().strftime("%Y%m%d")}.xlsx'
        )
        
    except Exception as e:
        print(f"Error exporting licenses: {str(e)}")
        flash('Error exporting licenses!', 'danger')
        return redirect(url_for('manage_licenses'))

@app.route('/api/businesses/<user_id>')
def get_user_businesses(user_id):
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
        
    try:
        # Get all applications for the user
        user_applications = list(applications.find({
            'user_id': ObjectId(user_id),
            'status': 'approved'  # Only get approved applications
        }))
        
        # Format business data
        business_list = []
        for app in user_applications:
            business_list.append({
                '_id': str(app['_id']),
                'business_name': app.get('business_name', ''),
                'business_address': app.get('business_address', ''),
                'contact_person': app.get('contact_person', ''),
                'contact_number': app.get('contact_number', ''),
                'email': app.get('email', '')
            })
            
        return jsonify({'businesses': business_list})
    except Exception as e:
        print(f"Error fetching businesses: {str(e)}")
        return jsonify({'error': str(e)}), 500

# @app.route('/api/licenses/create', methods=['POST'])
# def create_new_license():
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
        
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['userId', 'businessId', 'businessName', 'businessAddress', 
                         'contactPerson', 'contactNumber', 'email']
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400
            
        # Get user details
        user = users.find_one({'_id': ObjectId(data['userId'])})
        if not user:
            return jsonify({'error': 'User not found'}), 404
            
        # Get business application
        business_app = applications.find_one({'_id': ObjectId(data['businessId'])})
        if not business_app:
            return jsonify({'error': 'Business application not found'}), 404
            
        # Generate license number
        license_number = generate_license_number()
        
        # Create license data
        license_data = {
            'license_number': license_number,
            'user_id': ObjectId(data['userId']),
            'application_id': ObjectId(data['businessId']),
            'business_name': data['businessName'],
            'business_address': data['businessAddress'],
            'owner_name': data['contactPerson'],
            'contact_number': data['contactNumber'],
            'email': data['email'],
            'issue_date': datetime.now(),
            'expiry_date': datetime.now() + timedelta(days=365),
            'status': 'active',
            'renewals': [],
            'created_at': datetime.now(),
            'created_by': session['username']
        }
        
        # Insert license
        result = licenses.insert_one(license_data)
        
        # Update application with license reference
        applications.update_one(
            {'_id': ObjectId(data['businessId'])},
            {'$set': {'license_id': str(result.inserted_id)}}
        )
        
        # Generate PDF
        pdf_buffer = generate_license_pdf(license_data)
        
        # Send email with PDF attachment
        subject = "New Fire Safety License Generated"
        body = f"""
        Dear {data['contactPerson']},

        Your Fire Safety License has been generated successfully:

        License Details:
        - License Number: {license_number}
        - Business Name: {data['businessName']}
        - Issue Date: {license_data['issue_date'].strftime('%Y-%m-%d')}
        - Expiry Date: {license_data['expiry_date'].strftime('%Y-%m-%d')}

        Please find your license certificate attached to this email.
        Keep this license number for future reference.

        Best regards,
        Fire Safety Department
        """
        send_email_with_attachment(
            subject=subject,
            recipient=data['email'],
            body=body,
            attachment=pdf_buffer.getvalue(),
            attachment_name=f"license_{license_number}.pdf",
            attachment_type="application/pdf"
        )
        
        return jsonify({
            'success': True,
            'message': 'License generated and sent successfully',
            'license_id': str(result.inserted_id)
        })
        
    except Exception as e:
        print(f"Error creating license: {str(e)}")
        return jsonify({'error': str(e)}), 500

def generate_license_pdf(license_data):
    """Generate a PDF for the license"""
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []
    
    # Title
    elements.append(Paragraph('FIRE SAFETY LICENSE', styles['Title']))
    elements.append(Spacer(1, 20))
    
    # License details
    elements.extend([
        Paragraph(f'License Number: {license_data["license_number"]}', styles['Normal']),
        Paragraph(f'Business Name: {license_data["business_name"]}', styles['Normal']),
        Paragraph(f'Business Address: {license_data["business_address"]}', styles['Normal']),
        Paragraph(f'Owner Name: {license_data["owner_name"]}', styles['Normal']),
        Paragraph(f'Contact Number: {license_data["contact_number"]}', styles['Normal']),
        Paragraph(f'Issue Date: {license_data["issue_date"].strftime("%Y-%m-%d")}', styles['Normal']),
        Paragraph(f'Expiry Date: {license_data["expiry_date"].strftime("%Y-%m-%d")}', styles['Normal']),
        Spacer(1, 20)
    ])
    
    # Terms and conditions
    elements.extend([
        Paragraph('Terms and Conditions:', styles['Heading2']),
        Paragraph('1. This license must be displayed prominently at the business premises.', styles['Normal']),
        Paragraph('2. Regular fire safety inspections must be conducted.', styles['Normal']),
        Paragraph('3. Fire safety equipment must be maintained as per regulations.', styles['Normal']),
        Paragraph('4. License must be renewed before expiry date.', styles['Normal']),
        Spacer(1, 30)
    ])
    
    # Signature
    elements.extend([
        Paragraph('Authorized Signature:', styles['Normal']),
        Spacer(1, 20),
        Paragraph('_______________________', styles['Normal']),
        Paragraph('Fire Safety Department', styles['Normal'])
    ])
    
    doc.build(elements)
    buffer.seek(0)
    return buffer

def send_email_with_attachment(subject, recipient, body, attachment, attachment_name, attachment_type):
    """Send email with PDF attachment"""
    try:
        msg = Message(subject, recipients=[recipient])
        msg.body = body
        msg.attach(attachment_name, attachment_type, attachment)
        mail.send(msg)
        return True
    except Exception as e:tion
        print(f"Error sending email with attachment: {str(e)}")
        return False

if __name__ == '__main__':    return send_from_directory(app.static_folder, filename)




    socketio.run(app, debug=True)        os.makedirs(app.config['UPLOAD_FOLDER'])    if not os.path.exists(app.config['UPLOAD_FOLDER']):
# Add health check endpoint
@app.route('/health')
def health_check():
    return jsonify({'status': 'healthy'}), 200

if __name__ == '__main__':

    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    socketio.run(app, debug=True)