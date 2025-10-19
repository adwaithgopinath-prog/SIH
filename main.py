from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_mail import Mail, Message
from functools import wraps
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from apscheduler.schedulers.background import BackgroundScheduler
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
import logging

# ----------------------
# App setup
# ----------------------
app = Flask(__name__)
app.secret_key = "supersecretkey"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['MAIL_SERVER'] = 'sandbox.smtp.mailtrap.io'
app.config['MAIL_PORT'] = 2525
app.config['MAIL_USERNAME'] = 'your_mailtrap_username'
app.config['MAIL_PASSWORD'] = 'your_mailtrap_password'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)
mail = Mail(app)

# ----------------------
# Logging
# ----------------------
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s]: %(message)s')

# ----------------------
# Constants
# ----------------------
ROLE_PATIENT = "patient"
ROLE_THERAPIST = "therapist"
ROLE_ADMIN = "admin"

STATUS_UPCOMING = "Upcoming"
STATUS_COMPLETED = "Completed"
STATUS_MISSED = "Missed"
STATUS_CANCELED = "Canceled"

# ----------------------
# Database Models
# ----------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(100), nullable=True)
    profile = db.relationship("PatientProfile", backref="user", uselist=False)

class PatientProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    dob = db.Column(db.Date)
    gender = db.Column(db.String(30))
    mobile_number = db.Column(db.String(20))
    email = db.Column(db.String(100))
    blood_group = db.Column(db.String(10))
    marital_status = db.Column(db.String(20))
    address = db.Column(db.String(200))
    city = db.Column(db.String(50))
    state = db.Column(db.String(50))
    pin_code = db.Column(db.String(10))
    chronic_conditions = db.Column(db.String(300))
    allergies = db.Column(db.String(300))
    allergy_details = db.Column(db.String(300))
    current_medications = db.Column(db.String(300))
    supplements_vitamins = db.Column(db.String(300))
    previous_surgeries = db.Column(db.String(300))
    previous_ayurvedic_treatments = db.Column(db.String(300))
    exercise = db.Column(db.String(50))
    smoking_status = db.Column(db.String(50))
    alcohol = db.Column(db.String(50))
    diet_plan = db.Column(db.String(50))

class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    therapist_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    start_time = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default=STATUS_UPCOMING)
    attended = db.Column(db.Boolean, default=None)
    notes = db.Column(db.Text)
    patient = db.relationship('User', foreign_keys=[patient_id], backref='bookings', lazy=True)
    therapist = db.relationship('User', foreign_keys=[therapist_id], lazy=True)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    sender = db.relationship("User", foreign_keys=[sender_id], backref="sent_messages")
    receiver = db.relationship("User", foreign_keys=[receiver_id], backref="received_messages")

# ----------------------
# Login Required Decorator
# ----------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please login first.", "danger")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ----------------------
# Email Setup
# ----------------------
EMAIL_ADDRESS = "your_email@gmail.com"
EMAIL_PASSWORD = "your_email_password"

def send_email(to_email, subject, body):
    if not to_email:
        logging.warning(f"Skipping email for subject '{subject}' because email is None")
        return
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        logging.info(f"Email sent to {to_email} with subject '{subject}'")
    except Exception as e:
        logging.error(f"Failed to send email to {to_email}: {e}")

# ----------------------
# Setup / default users
# ----------------------
def create_default_users():
    defaults = [
        (ROLE_PATIENT, "patient1", "patient123", "patient1@example.com"),
        (ROLE_THERAPIST, "therapist1", "therapist123", "therapist1@example.com"),
        (ROLE_ADMIN, "admin1", "admin123", "admin1@example.com")
    ]
    for role, username, pwd, email in defaults:
        if not User.query.filter_by(username=username).first():
            user = User(username=username, password=generate_password_hash(pwd), role=role, email=email)
            db.session.add(user)
    db.session.commit()

# ----------------------
# Scheduler for missed sessions
# ----------------------
def update_past_bookings():
    now = datetime.now()
    past_bookings = Booking.query.filter(Booking.start_time < now, Booking.attended.is_(None), Booking.status==STATUS_UPCOMING).all()
    for b in past_bookings:
        b.status = STATUS_MISSED
        b.attended = False
        db.session.commit()
        send_email(b.patient.email, "Session Missed", f"Your session with {b.therapist.username if b.therapist else 'therapist'} on {b.start_time} was missed.")
        if b.therapist and b.therapist.email:
            send_email(b.therapist.email, "Session Missed", f"The session with patient {b.patient.username} on {b.start_time} was missed.")
        logging.info(f"Booking {b.id} marked as missed")

scheduler = BackgroundScheduler()
scheduler.add_job(func=update_past_bookings, trigger="interval", minutes=5)

@app.before_request
def initialize():
    db.create_all()
    create_default_users()
    try:
        scheduler.start()
        logging.info("Scheduler started successfully")
    except Exception as e:
        logging.warning(f"Scheduler start failed or already running: {e}")

# ----------------------
# Serializer for password reset
# ----------------------
serializer = URLSafeTimedSerializer(app.secret_key)

# ----------------------
# Routes
# ----------------------
@app.route("/")
def index():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session["user_id"] = user.id
            session["username"] = user.username
            session["role"] = user.role
            flash(f"Welcome {user.username}!", "success")
            if user.role == ROLE_ADMIN:
                return redirect(url_for("admin_dashboard"))
            elif user.role == ROLE_THERAPIST:
                return redirect(url_for("therapist_dashboard"))
            else:
                return redirect(url_for("patient_dashboard"))
        else:
            flash("Invalid username or password", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for("login"))

# ----------------------
# Dashboards
# ----------------------
@app.route("/patient/dashboard")
@login_required
def patient_dashboard():
    if session.get("role") != ROLE_PATIENT:
        flash("Access denied!", "danger")
        return redirect(url_for("login"))
    user_id = session["user_id"]
    user = User.query.get(user_id)
    bookings = Booking.query.filter_by(patient_id=user_id).all()
    profile = PatientProfile.query.filter_by(user_id=user_id).first()
    return render_template("patient_dashboard.html", current_user=session["username"], bookings=bookings, profile=profile)

@app.route("/therapist/dashboard")
@login_required
def therapist_dashboard():
    if session.get("role") != ROLE_THERAPIST:
        flash("Access denied!", "danger")
        return redirect(url_for("login"))
    user_id = session["user_id"]
    bookings = Booking.query.filter_by(therapist_id=user_id).all()
    messages = Message.query.filter((Message.sender_id==user_id)|(Message.receiver_id==user_id)).order_by(Message.created_at.desc()).limit(5).all()
    return render_template("therapist_dashboard.html", current_user=session["username"], bookings=bookings, messages=messages)

@app.route("/admin/dashboard")
@login_required
def admin_dashboard():
    if session.get("role") != ROLE_ADMIN:
        flash("Access denied!", "danger")
        return redirect(url_for("login"))
    patients = User.query.filter_by(role=ROLE_PATIENT).all()
    therapists = User.query.filter_by(role=ROLE_THERAPIST).all()
    return render_template("admin_dashboard.html", username=session["username"], patients=patients, therapists=therapists)

# ----------------------
#  Admin(uprade)
# ----------------------
@app.route('/admin/add_patient', methods=['GET', 'POST'])
@login_required
def add_patient():
    if session.get("role") != ROLE_ADMIN:
        flash("Access denied!", "danger")
        return redirect(url_for("login"))

    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        age = request.form.get("age")
        gender = request.form.get("gender")
        contact = request.form.get("contact")
        address = request.form.get("address")

        # Check if username already exists
        if User.query.filter_by(username=username).first():
            flash("Username already exists.", "danger")
            return redirect(url_for("add_patient"))

        # Create User
        user = User(username=username, password=generate_password_hash(password), role=ROLE_PATIENT, email=email)
        db.session.add(user)
        db.session.commit()

        # Optional: create a PatientProfile
        profile = PatientProfile(
            user_id=user.id,
            gender=gender,
            mobile_number=contact,
            address=address
        )
        db.session.add(profile)
        db.session.commit()

        flash("Patient added successfully!", "success")
        return redirect(url_for("admin_dashboard"))

    return render_template("add_patient.html")

@app.route('/admin/add_therapist', methods=['GET', 'POST'])
@login_required
def add_therapist():
    # Only admin can access
    if session.get("role") != ROLE_ADMIN:
        flash("Access denied!", "danger")
        return redirect(url_for("login"))

    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")

        # Check if username already exists
        if User.query.filter_by(username=username).first():
            flash("Username already exists.", "danger")
            return redirect(url_for("add_therapist"))

        # Create Therapist user
        therapist = User(
            username=username,
            password=generate_password_hash(password),
            role=ROLE_THERAPIST,
            email=email
        )
        db.session.add(therapist)
        db.session.commit()

        flash("Therapist added successfully!", "success")
        return redirect(url_for("admin_dashboard"))

    return render_template("add_therapist.html")

@app.route('/delete_patient/<int:user_id>', methods=['POST'])
@login_required
def delete_patient(user_id):
    user = User.query.get(user_id)
    if user and user.role == ROLE_PATIENT:
        db.session.delete(user)
        db.session.commit()
        flash("Patient deleted successfully.", "success")
    else:
        flash("Patient not found.", "danger")
    return redirect(url_for('admin_dashboard'))

@app.route('/delete_therapist/<int:user_id>', methods=['POST'])
@login_required
def delete_therapist(user_id):
    user = User.query.get(user_id)
    if user and user.role == ROLE_THERAPIST:
        db.session.delete(user)
        db.session.commit()
        flash("Therapist deleted successfully.", "success")
    else:
        flash("Therapist not found.", "danger")
    return redirect(url_for('admin_dashboard'))



# ----------------------
# Signup steps
# ----------------------
@app.route("/signup/step1", methods=["GET","POST"])
def signup_step1():
    if request.method=="POST":
        session["personal_info"] = request.form.to_dict()
        return redirect(url_for("signup_step2"))
    return render_template("signup_step1.html")

@app.route("/signup/step2", methods=["GET","POST"])
def signup_step2():
    if request.method=="POST":
        session["medical_history_lifestyle"] = request.form.to_dict()
        return redirect(url_for("signup_step4"))
    return render_template("signup_step2.html")

@app.route("/signup/step4", methods=["GET","POST"])
def signup_step4():
    personal_info = session.get("personal_info")
    med_life = session.get("medical_history_lifestyle")
    if not personal_info or not med_life:
        flash("Please complete previous steps first.", "danger")
        return redirect(url_for("signup_step1"))
    if request.method=="POST":
        username = personal_info.get("username")
        password = personal_info.get("password")
        email = personal_info.get("email") or f"{username}@example.com"
        if not username or not password:
            flash("Username and password cannot be empty.", "danger")
            return redirect(url_for("signup_step1"))
        if User.query.filter_by(username=username).first():
            flash("Username already exists.", "danger")
            return redirect(url_for("signup_step1"))
        user = User(username=username, password=generate_password_hash(password), role=ROLE_PATIENT, email=email)
        db.session.add(user)
        db.session.commit()
        dob = personal_info.get("dob")
        dob_parsed = datetime.strptime(dob, "%Y-%m-%d") if dob else None
        profile = PatientProfile(
            user_id=user.id,
            first_name=personal_info.get("first_name"),
            last_name=personal_info.get("last_name"),
            dob=dob_parsed,
            gender=personal_info.get("gender"),
            mobile_number=personal_info.get("mobile_number"),
            email=email,
            blood_group=personal_info.get("blood_group"),
            marital_status=personal_info.get("marital_status"),
            address=personal_info.get("address"),
            city=personal_info.get("city"),
            state=personal_info.get("state"),
            pin_code=personal_info.get("pin_code"),
            chronic_conditions=med_life.get("chronic_conditions"),
            allergies=med_life.get("allergies"),
            allergy_details=med_life.get("allergy_details"),
            current_medications=med_life.get("current_medications"),
            supplements_vitamins=med_life.get("supplements_vitamins"),
            previous_surgeries=med_life.get("previous_surgeries"),
            previous_ayurvedic_treatments=med_life.get("previous_ayurvedic_treatments"),
            exercise=med_life.get("exercise"),
            smoking_status=med_life.get("smoking_status"),
            alcohol=med_life.get("alcohol"),
            diet_plan=med_life.get("diet_plan")
        )
        db.session.add(profile)
        db.session.commit()
        session.clear()
        flash("Signup complete! Please login.", "success")
        return redirect(url_for("login"))
    return render_template("signup_step4.html", personal_info=personal_info, med_life=med_life)

# ----------------------
# Profile page
# ----------------------
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user_id = session.get("user_id")
    user = User.query.get(user_id)
    profile = user.profile
    if request.method == 'POST':
        profile.first_name = request.form.get('first_name')
        profile.last_name = request.form.get('last_name')
        dob = request.form.get('dob')
        profile.dob = datetime.strptime(dob, "%Y-%m-%d") if dob else None
        profile.gender = request.form.get('gender')
        profile.mobile_number = request.form.get('mobile_number')
        profile.email = request.form.get('email')
        profile.blood_group = request.form.get('blood_group')
        profile.marital_status = request.form.get('marital_status')
        profile.address = request.form.get('address')
        profile.city = request.form.get('city')
        profile.state = request.form.get('state')
        profile.pin_code = request.form.get('pin_code')
        profile.chronic_conditions = request.form.get('chronic_conditions')
        profile.allergies = request.form.get('allergies')
        profile.allergy_details = request.form.get('allergy_details')
        profile.current_medications = request.form.get('current_medications')
        profile.supplements_vitamins = request.form.get('supplements_vitamins')
        profile.previous_surgeries = request.form.get('previous_surgeries')
        profile.previous_ayurvedic_treatments = request.form.get('previous_ayurvedic_treatments')
        profile.exercise = request.form.get('exercise')
        profile.smoking_status = request.form.get('smoking_status')
        profile.alcohol = request.form.get('alcohol')
        profile.diet_plan = request.form.get('diet_plan')
        db.session.commit()
        flash("Profile updated successfully!", "success")
        return redirect(url_for('profile'))
    return render_template('profile.html', profile=profile)

# ----------------------
# Book session
# ----------------------
@app.route('/book', methods=['GET','POST'])
@login_required
def book():
    user = User.query.get(session['user_id'])
    therapists = User.query.filter_by(role=ROLE_THERAPIST).all()
    if request.method=='POST':
        start_time_str = request.form.get('start_time')
        if not start_time_str:
            flash("Please provide a start time.", "danger")
            return redirect(url_for('book'))
        start_time = datetime.fromisoformat(start_time_str)
        therapist_id = request.form['therapist_id']
        notes = request.form.get('notes')
        booking = Booking(patient_id=user.id, therapist_id=therapist_id, start_time=start_time, notes=notes)
        db.session.add(booking)
        db.session.commit()
        flash("Session booked successfully!", "success")
        therapist = User.query.get(therapist_id)
        send_email(user.email, "Session Scheduled", f"Your session with {therapist.username} is scheduled at {start_time}.")
        send_email(therapist.email, "Session Scheduled", f"Your session with {user.username} is scheduled at {start_time}.")
        return redirect(url_for('book'))
    bookings = Booking.query.filter_by(patient_id=user.id).all()
    return render_template('book.html', bookings=bookings, therapists=therapists)

# ----------------------
# Update booking status
# ----------------------
@app.route('/update_booking_status/<int:booking_id>/<new_status>', methods=['POST'])
@login_required
def update_booking_status(booking_id, new_status):
    booking = Booking.query.get(booking_id)
    if booking:
        booking.status = new_status
        booking.attended = True if new_status==STATUS_COMPLETED else False
        db.session.commit()
        flash(f"Booking marked as {new_status}.", "success")
        return redirect(url_for('schedule'))
    flash("Booking not found.", "danger")
    return redirect(url_for('schedule'))

# ----------------------
# Schedule / cancel session
# ----------------------
@app.route('/schedule', methods=['GET','POST'])
@login_required
def schedule():
    user = User.query.get(session['user_id'])
    if request.method=='POST':
        cancel_id = request.form.get('cancel_booking_id')
        if cancel_id:
            booking = Booking.query.get(cancel_id)
            if booking:
                booking.status = STATUS_CANCELED
                booking.attended = False
                db.session.commit()
                flash("Booking canceled.", "success")
                send_email(booking.patient.email, "Session Canceled", f"Your session was canceled.")
                if booking.therapist and booking.therapist.email:
                    send_email(booking.therapist.email, "Session Canceled", f"The session with patient {booking.patient.username} was canceled.")
            return redirect(url_for('schedule'))
    if user.role==ROLE_PATIENT:
        bookings = Booking.query.filter_by(patient_id=user.id).all()
    elif user.role==ROLE_THERAPIST:
        bookings = Booking.query.filter_by(therapist_id=user.id).all()
    else:
        bookings = Booking.query.all()
    total_sessions = len(bookings)
    upcoming_sessions = len([b for b in bookings if b.status==STATUS_UPCOMING])
    completed_sessions = len([b for b in bookings if b.status==STATUS_COMPLETED])
    canceled_sessions = len([b for b in bookings if b.status==STATUS_CANCELED])
    missed_sessions = len([b for b in bookings if b.status==STATUS_MISSED])
    return render_template('schedule.html', bookings=bookings, total_sessions=total_sessions,
                           upcoming_sessions=upcoming_sessions, completed_sessions=completed_sessions,
                           canceled_sessions=canceled_sessions, missed_sessions=missed_sessions)

# ----------------------
# Update username (AJAX)
# ----------------------
@app.route("/update_username/<int:user_id>", methods=["POST"])
@login_required
def update_username(user_id):
    try:
        data = request.get_json()
        new_username = data.get("username", "").strip()
        if not new_username:
            return jsonify({"status": "error", "message": "Username cannot be empty."}), 400
        user = User.query.get(user_id)
        if not user:
            return jsonify({"status": "error", "message": "User not found."}), 404
        existing_user = User.query.filter(User.username == new_username, User.id != user_id).first()
        if existing_user:
            return jsonify({"status": "error", "message": "Username already exists."}), 409
        user.username = new_username
        db.session.commit()
        return jsonify({"status": "success", "message": "Username updated successfully!"}), 200
    except Exception as e:
        db.session.rollback()
        print("Error updating username:", e)
        return jsonify({"status": "error", "message": "Internal server error."}), 500

# ----------------------
# Messaging
# ----------------------
@app.route('/messages', methods=['GET', 'POST'])
@login_required
def messages():
    user_id = session['user_id']
    user_role = session['role']

    # Only show relevant contacts
    if user_role == ROLE_PATIENT:
        users = User.query.filter_by(role=ROLE_THERAPIST).all()
    elif user_role == ROLE_THERAPIST:
        users = User.query.filter_by(role=ROLE_PATIENT).all()
    else:
        users = []  # admin or others, empty list

    # Check if a specific user chat is selected
    selected_user_id = request.args.get('user_id')
    selected_user = User.query.get(int(selected_user_id)) if selected_user_id else None

    # Handle sending a new message
    if request.method == 'POST':
        content = request.form['content']
        receiver_id = request.form.get('receiver_id')
        if receiver_id:
            msg = Message(sender_id=user_id,
                          receiver_id=int(receiver_id),
                          content=content,
                          created_at=datetime.utcnow())
            db.session.add(msg)
            db.session.commit()
            return redirect(url_for('messages', user_id=receiver_id))

    # Fetch messages between logged-in user and selected user
    messages_list = []
    if selected_user:
        messages_list = Message.query.filter(
            ((Message.sender_id == user_id) & (Message.receiver_id == selected_user.id)) |
            ((Message.sender_id == selected_user.id) & (Message.receiver_id == user_id))
        ).order_by(Message.created_at).all()

    return render_template(
        'messages.html',
        users=users,
        selected_user=selected_user,
        messages=messages_list,
        current_user_id=user_id
    )



# ----------------------
# Reports
# ----------------------
@app.route('/reports')
@login_required
def reports():
    user = User.query.get(session['user_id'])
    if user.role == ROLE_ADMIN:
        bookings = Booking.query.all()
    elif user.role == ROLE_THERAPIST:
        bookings = Booking.query.filter_by(therapist_id=user.id).all()
    else:
        bookings = Booking.query.filter_by(patient_id=user.id).all()
    total_sessions = len(bookings)
    upcoming_sessions = len([b for b in bookings if b.status==STATUS_UPCOMING])
    completed_sessions = len([b for b in bookings if b.status==STATUS_COMPLETED])
    canceled_sessions = len([b for b in bookings if b.status==STATUS_CANCELED])
    missed_sessions = len([b for b in bookings if b.status==STATUS_MISSED])
    return render_template('reports.html', current_user=user.username, bookings=bookings,
                           total_sessions=total_sessions, upcoming_sessions=upcoming_sessions,
                           completed_sessions=completed_sessions, canceled_sessions=canceled_sessions,
                           missed_sessions=missed_sessions)

# ----------------------
# Forgot / Reset Password
# ----------------------
@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email")
        if not email:
            flash("Please enter your registered email address.", "danger")
            return redirect(url_for("forgot_password"))
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("No account found with that email.", "danger")
            return redirect(url_for("forgot_password"))
        token = serializer.dumps(email, salt="password-reset-salt")
        reset_link = url_for("reset_password", token=token, _external=True)
        subject = "Password Reset Request"
        body = f"Hi {user.username},\n\nReset your password here:\n{reset_link}\n\nIf you didn't request this, ignore this email."
        send_email(email, subject, body)
        flash("Password reset link has been sent to your email.", "success")
        return redirect(url_for("login"))
    return render_template("forgot_password.html")

@app.route("/reset_password/<token>", methods=["GET","POST"])
def reset_password(token):
    try:
        email = serializer.loads(token, salt="password-reset-salt", max_age=900)
    except SignatureExpired:
        flash("The reset link has expired.", "danger")
        return redirect(url_for("forgot_password"))
    except BadTimeSignature:
        flash("Invalid reset link.", "danger")
        return redirect(url_for("forgot_password"))
    user = User.query.filter_by(email=email).first()
    if request.method=="POST":
        new_password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        if not new_password or not confirm_password:
            flash("Please fill in both fields.", "danger")
            return redirect(url_for("reset_password", token=token))
        if new_password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("reset_password", token=token))
        user.password = generate_password_hash(new_password)
        db.session.commit()
        flash("Your password has been reset successfully!", "success")
        return redirect(url_for("login"))
    return render_template("reset_password.html")

# ----------------------
# Run App
# ----------------------
if __name__ == "__main__":
    app.run(debug=True)
