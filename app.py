import os, sys, random, razorpay
from dotenv import load_dotenv
import cloudinary.uploader
import smtplib, traceback
from sqlalchemy import or_
from datetime import datetime
from email.mime.text import MIMEText
from flask_login import login_required, LoginManager, login_user, current_user
from flask import Flask, request, jsonify, render_template, redirect, session, url_for, flash, abort
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash
from models import db, ServiceProvider, ProviderProfileWork, Appointment

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)


app = Flask(__name__)
load_dotenv()
app.secret_key = os.getenv('secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('url_db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] =  1 * 1024 * 1024
app.config['ALLOWED_EXTENSIONS'] = {'pdf', 'jpg', 'jpeg', 'png'}

cloudinary.config(
  cloud_name=os.getenv('CLOUDINARY_CLOUD_NAME'),
  api_key=os.getenv('CLOUDINARY_API_KEY'),
  api_secret=os.getenv('CLOUDINARY_API_SECRET'),
  secure=True
)
db.init_app(app)

RAZORPAY_KEY_ID = os.getenv('RAZORPAY_KEY_ID')
RAZORPAY_KEY_SECRET = os.getenv('RAZORPAY_KEY_SECRET')
razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))


login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return ServiceProvider.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def get_logged_in_provider():
    provider_id = session.get('provider_id')
    if not provider_id:
        return None
    return ServiceProvider.query.get(provider_id)

def send_verification_email(to_email, code):
    smtp_server = os.getenv('server')
    smtp_port = os.getenv('port')
    sender_email = os.getenv('email')
    sender_password = os.getenv('password') 

    subject = "OTP for E-Mail verification"
    body = f"Your OTP for E-Mail verification is {code} valid only for 2 minutes. Do not share with anyone."

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = sender_email
    msg['To'] = to_email

    server = smtplib.SMTP(smtp_server, smtp_port)
    server.starttls()
    server.login(sender_email, sender_password)
    server.sendmail(sender_email, to_email, msg.as_string())
    server.quit()

@app.route('/')
def home():
    return render_template("landing.html")

@app.route('/provider/apply')
def provider_apply():
    return render_template("returing.html")

@app.route('/provider/verify')
def provider_verify():
    return render_template("verify.html")

@app.route('/provider/login1')
def provider_login1():
    return render_template("login.html")

@login_manager.unauthorized_handler
def unauthorized_callback():
    if request.accept_mimetypes.accept_json:
        return jsonify({'error': 'Unauthorized'}), 401
    return redirect(url_for('provider_login'))


@app.route('/provider/check_aadhar', methods=['POST'])
def check_aadhar():
    data = request.get_json()
    aadhar = data.get('aadhar')

    if not aadhar or len(aadhar) != 12 or not aadhar.isdigit():
        return jsonify({'error': 'Invalid Aadhar number.'}), 400

    provider = ServiceProvider.query.filter_by(aadhar=aadhar).first()

    if provider:
        if provider.approved:
            return jsonify({
                'exists': True,
                'status': 'Approved',
                'username': provider.username or '',
            })
        else:
            return jsonify({
                'exists': True,
                'status': 'Pending approval'
            })
    else:
        return jsonify({'exists': False})


@app.route('/provider/apply1', methods=['POST'])
def provider_apply1():
    try:
        form = request.form
        required_fields = ['shop_location', 'owner_name', 'phone', 'email', 'aadhar']
        for field in required_fields:
            if not form.get(field):
                return jsonify({'error': f'Missing field: {field}'}), 400

        aadhar = form.get('aadhar')
        existing = ServiceProvider.query.filter_by(aadhar=aadhar).first()
        if existing:
            return jsonify({'error': 'Aadhar already registered'}), 400

        
        def upload_to_cloudinary(file, folder='provider_docs'):
            ext = file.filename.rsplit('.', 1)[-1].lower()
            resource_type = 'image' if ext in {'jpg', 'jpeg', 'png'} else 'raw'

            upload_result = cloudinary.uploader.upload(
                file,
                folder=folder,
                resource_type=resource_type
            )
            return upload_result['secure_url']

        
        gst_doc = request.files.get('gst_doc')
        aadhar_doc = request.files.get('aadhar_doc')

        gst_doc_url = upload_to_cloudinary(gst_doc) if gst_doc and allowed_file(gst_doc.filename) else None
        aadhar_doc_url = upload_to_cloudinary(aadhar_doc) if aadhar_doc and allowed_file(aadhar_doc.filename) else None

        
        uploaded_additional_docs = []
        for file in request.files.getlist('additional_docs'):
            if file and allowed_file(file.filename):
                doc_url = upload_to_cloudinary(file)
                uploaded_additional_docs.append(doc_url)

        provider = ServiceProvider(
            username=form.get('email').lower(),
            email=form.get('email'),
            phone_number=form.get('phone'),
            aadhar=aadhar,
            name=form.get('owner_name'),
            address=form.get('shop_location'),
            documents=str([gst_doc_url, aadhar_doc_url] + uploaded_additional_docs),
            approved=False
        )
        provider.set_password('xxxxxx')  
        db.session.add(provider)
        db.session.commit()

        return jsonify({'message': 'Registration submitted successfully, pending admin approval.'})

    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500




@app.route('/provider/login', methods=['GET', 'POST'])
def provider_login():
    if request.method == 'GET':
        return render_template('login.html')

    username = request.form.get('username').lower()
    password = request.form.get('password')

    if not username or not password:
        flash('Please enter both username and password.', 'error')
        return redirect(url_for('provider_login'))

    provider = ServiceProvider.query.filter_by(username=username).first()

    if not provider or not provider.check_password(password):
        flash('Invalid username or password.', 'error')
        return redirect(url_for('provider_login'))

    if not provider.approved:
        flash('Your account is not yet approved by admin.', 'error')
        return redirect(url_for('provider_login'))

    session['provider_id'] = provider.id
    session['username'] = provider.username
    flash('Logged in successfully!', 'success')
    login_user(provider)
    return redirect(url_for('provider_dashboard'))

@app.route('/provider/dashboard')
def provider_dashboard():
    if 'provider_id' not in session:
        return redirect(url_for('provider_login'))
    return render_template('dashboard.html')

@app.route('/provider/profile', methods=['GET'])
@login_required
def profile_page():
    user = current_user
    photos = ProviderProfileWork.query.filter_by(provider_id=user.id).all()

    photos_data = [
        {
            'id': p.id,
            'url': p.image_path  
        } for p in photos
    ]

    return jsonify({
        'username': user.username,
        'skills': user.skills,
        'photos': photos_data
    })


@app.route('/provider/update_profile', methods=['POST'])
def update_profile():
    user = current_user
    data = request.get_json()
    skills = data.get('skills')

    if skills is None:
        return jsonify({'message': 'Skills are required'}), 400

    user.skills = skills
    db.session.commit()

    return jsonify({'message': 'Profile updated successfully.'})

@app.route('/provider/upload_photos', methods=['POST'])
@login_required
def upload_photos():
    user = current_user

    if 'photos' not in request.files:
        return jsonify({'message': 'No photos part in request'}), 400

    files = request.files.getlist('photos')
    if not files:
        return jsonify({'message': 'No files selected'}), 400

    saved_photos = []

    for file in files:
        if file.filename == '':
            continue

        filename = secure_filename(f"{user.username}_{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}_{file.filename}")
        upload_result = cloudinary.uploader.upload(file, folder="provider_photos")

        if not upload_result.get('secure_url'):
            continue  

        cloudinary_url = upload_result['secure_url']

        new_photo = ProviderProfileWork(
            provider_id=user.id,
            image_path=cloudinary_url 
        )

        db.session.add(new_photo)
        saved_photos.append(cloudinary_url)

    db.session.commit()

    return jsonify({'message': f'{len(saved_photos)} photo(s) uploaded successfully.'})


@app.route('/provider/delete_photo/<int:photo_id>', methods=['DELETE'])
def delete_photo(photo_id):
    user = current_user
    photo = ProviderProfileWork.query.filter_by(id=photo_id, provider_id=user.id).first()
    if not photo:
        return jsonify({'message': 'Photo not found or unauthorized'}), 404

    try:
        if os.path.exists(photo.image_path):
            os.remove(photo.image_path)
    except Exception as e:
        print(f"Error deleting file: {e}")

    db.session.delete(photo)
    db.session.commit()
    return jsonify({'message': 'Photo deleted successfully.'})



@app.route('/provider/logout')
def provider_logout():
    session.pop('provider_id', None)
    flash('Logged out successfully.', 'success')
    return redirect(url_for('provider_login'))


def send_email(to_email, subject, body):
    print(f"Sending email to {to_email}:\nSubject: {subject}\nBody: {body}")



@app.route('/provider/verify_email', methods=['POST'])
def verify_email():
    username = request.form.get('username')  
    if not username:
        return jsonify({"error": "Username is required"}), 400

    provider = ServiceProvider.query.filter_by(username=username).first()

    if not provider:
        flash("Provider not found", "error")
        return redirect(url_for('verify_email'))

    code = str(random.randint(100000, 999999))
    session['verification_code'] = code
    session['username'] = username

    send_verification_email(provider.email, code)

    flash("Verification code sent to your email.", "info")
    return render_template('verify.html')

@app.route('/provider/verify_code', methods=['POST'])
def verify_code():
    code = request.form.get('code')

    if not code:
        flash("Verification code is required.", "error")
        return redirect(url_for('provider_verify'))

    expected_code = session.get('verification_code')
    username = session.get('username')

    if not expected_code or not username:
        flash("Session expired or invalid. Please start verification again.", "error")
        return redirect(url_for('provider_verify'))

    
    if code != expected_code:
        flash("Invalid verification code.", "error")
        return redirect(url_for('provider_verify'))

    flash("Verification successful. You can now set your password.", "success")
    session.pop('verification_code', None)

    return redirect(url_for('set_password')) 




@app.route('/set_password', methods=['GET', 'POST'])
def set_password():
    if 'username' not in session:
        return redirect(url_for('provider_login'))

    username = session['username']

    if request.method == 'POST':
        pw1 = request.form.get('password')
        pw2 = request.form.get('confirm_password')

        
        if pw1 != pw2:
            flash('Passwords do not match.', 'error')
        elif len(pw1) < 8:
            flash('Password must be at least 8 characters long.', 'error')
        else:
            provider = ServiceProvider.query.filter_by(username=username).first()
            if not provider:
                flash('Something went wrong. Provider not found.', 'error')
                return redirect(url_for('provider_login'))

            provider.password_hash = generate_password_hash(pw1)
            db.session.commit()

            flash('Password set successfully! Please login.', 'success')

            session.pop('username', None)
            session.pop('verification_code', None)

            return redirect(url_for('provider_login'))

    return render_template('set_password.html')



@app.route('/provider/requests')
@login_required
def provider_requests():
    status = request.args.get('status', '').lower()  
    provider_id = current_user.id
    valid_statuses = ['new', 'cancelled', 'rescheduled', 'pending', 'completed']

    if status not in valid_statuses:
        return jsonify({"error": "Invalid status filter. Use new, pending, completed, cancelled, or scheduled."}), 400

    if status == 'pending':
        appointments = Appointment.query.filter(
            Appointment.provider_id == provider_id,
            or_(
                Appointment.status == 'Pending',
                Appointment.status == 'Pending_Rescheduled'
            )
        ).all()
    else:
        status_cap = status.capitalize()
        appointments = Appointment.query.filter_by(provider_id=provider_id, status=status_cap).all()

   
    result = []
    for appt in appointments:
        result.append({
            "id": appt.id,
            "user_id": appt.user_id,
            "gadget_type_id": appt.gadget_type_id,
            "model": appt.model,
            "purchase_date": appt.purchase_date.isoformat() if appt.purchase_date else None,
            "problem_description": appt.problem_description,
            "preferred_time": appt.preferred_time.isoformat() if appt.preferred_time else None,
            "status": appt.status,
            "cancel_reason": appt.cancel_reason,
            "reschedule_time": appt.reschedule_time.isoformat() if appt.reschedule_time else None,
            "created_at": appt.created_at.isoformat() if appt.created_at else None,
            "updated_at": appt.updated_at.isoformat() if appt.updated_at else None,
        })

    return jsonify({"success": True, "appointments": result}), 200



@app.route('/provider/cancel_request/<int:appointment_id>', methods=['POST'])
@login_required
def cancel_request(appointment_id):
    appointment = Appointment.query.filter_by(id=appointment_id, provider_id=current_user.id).first()
    if not appointment:
        abort(404, description="Appointment not found")

    
    if appointment.status not in ['New', 'Pending', 'Pending_Rescheduled']:
        abort(400, description="Only new or pending appointments can be cancelled")

    data = request.get_json()
    reason = data.get('reason')
    if not reason:
        abort(400, description="Cancellation reason is required")

    appointment.status = 'Cancelled'
    appointment.cancel_reason = reason
    db.session.commit()

    return jsonify({'message': 'Appointment cancelled successfully'})


@app.route('/provider/reschedule_request/<int:appointment_id>', methods=['POST'])
@login_required
def reschedule_request(appointment_id):
    appointment = Appointment.query.filter_by(id=appointment_id, provider_id=current_user.id).first()
    if not appointment:
        abort(404, description="Appointment not found")
    if appointment.status != 'New':
        abort(400, description="Only new appointments can be rescheduled")

    data = request.get_json()
    new_date_str = data.get('newDate')
    if not new_date_str:
        abort(400, description="New date and time is required")

    try:
        new_date = datetime.fromisoformat(new_date_str)
    except ValueError:
        abort(400, description="Invalid date format, expected ISO 8601")

    appointment.status = 'Rescheduled'
    appointment.reschedule_time = new_date
    db.session.commit()

    return jsonify({'message': 'Appointment rescheduled successfully'})


@app.route('/provider/accept_request/<int:appointment_id>', methods=['POST'])
@login_required
def accept_request(appointment_id):
    appointment = Appointment.query.filter_by(id=appointment_id, provider_id=current_user.id).first()
    if not appointment:
        abort(404, description="Appointment not found")
    if appointment.status != 'New':
        abort(400, description="Only new appointments can be accepted")

    appointment.status = 'Pending'
    db.session.commit()

    return jsonify({'message': 'Appointment accepted and marked as Pending'})


@app.route('/provider/complete_request/<int:appointment_id>', methods=['POST'])
@login_required
def complete_request(appointment_id):
    appointment = Appointment.query.filter_by(id=appointment_id, provider_id=current_user.id).first()
    if not appointment:
        abort(404, description="Appointment not found")

    
    if appointment.status not in ['Pending', 'Pending_Rescheduled']:
        abort(400, description="Only pending or rescheduled pending appointments can be marked as completed")

    appointment.status = 'Completed'
    db.session.commit()

    return jsonify({'message': 'Appointment marked as Completed'})


if __name__ == '__main__':
    app.run(host="localhost", port=5001)