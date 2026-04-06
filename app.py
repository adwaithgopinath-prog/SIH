from flask import Flask, render_template, request, redirect, url_for, flash, session
from models import db, User, Booking
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Database setup
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///sih.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["PERMANENT_SESSION_LIFETIME"] = 30 * 24 * 60 * 60 # 30 days
db.init_app(app)

# ----------------- MIDDLEWARE -----------------
@app.context_processor
def inject_user():
    user = None
    if "user_id" in session:
        user = User.query.get(session["user_id"])
    return dict(
        username=user.username if user else None,
        role=user.role if user else None,
        user=user
    )

# ----------------- ROUTES -----------------
@app.route("/")
def home():
    # Modern Landing page
    return render_template("landing.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(username=username, password=password).first()
        if user:
            session["user_id"] = user.id
            if request.form.get("remember"):
                session.permanent = True
            flash("Welcome back, " + user.username + "!", "success")
            if user.role == 'patient':
                return redirect(url_for("patient_dashboard"))
            elif user.role == 'therapist':
                return redirect(url_for("therapist_dashboard"))
            return redirect(url_for("admin_dashboard"))
        else:
            flash("Invalid username or password", "danger")
    return render_template("login_page.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        role = request.form.get("role", "patient")

        if User.query.filter_by(username=username).first():
            flash("Username already exists!", "danger")
            return redirect(url_for("signup"))

        new_user = User(username=username, password=password, role=role)
        db.session.add(new_user)
        db.session.commit()
        
        flash("Registration successful! Please login.", "success")
        return redirect(url_for("login"))
    return render_template("signup_page.html")

@app.route("/patient_dashboard")
def patient_dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    
    user = User.query.get(session["user_id"])
    bookings = Booking.query.filter_by(patient_id=user.id).order_by(Booking.start_time.desc()).all()
    return render_template("dashboard.html", bookings=bookings)

@app.route("/therapist_dashboard")
def therapist_dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    
    user = User.query.get(session["user_id"])
    bookings = Booking.query.filter_by(therapist_id=user.id).order_by(Booking.start_time.asc()).all()
    return render_template("therapist_dashboard.html", bookings=bookings)

@app.route("/admin_dashboard")
def admin_dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    # In a real app we'd check if user.role == 'admin'
    return render_template("admin_dashboard.html")

@app.route("/book", methods=["GET", "POST"])
def book():
    if "user_id" not in session:
        return redirect(url_for("login"))
    
    therapists = User.query.filter_by(role='therapist').all()
    
    if request.method == "POST":
        patient_id = session["user_id"]
        therapist_id = request.form["therapist_id"]
        start_time_str = request.form["start_time"]
        end_time_str = request.form["end_time"]
        notes = request.form.get("notes", "")

        try:
            start_time = datetime.strptime(start_time_str, "%Y-%m-%dT%H:%M")
            end_time = datetime.strptime(end_time_str, "%Y-%m-%dT%H:%M")
            
            new_booking = Booking(
                patient_id=patient_id, 
                therapist_id=therapist_id, 
                start_time=start_time, 
                end_time=end_time,
                notes=notes
            )
            db.session.add(new_booking)
            db.session.commit()
            flash("Therapy session booked successfully!", "success")
        except Exception as e:
            flash("Error booking session: " + str(e), "danger")
            
        return redirect(url_for("patient_dashboard"))

    return render_template("book.html", therapists=therapists)

@app.route("/reports")
def reports():
    if "user_id" not in session: return redirect(url_for("login"))
    user = User.query.get(session["user_id"])
    bookings = Booking.query.filter_by(patient_id=user.id).all() if user.role == 'patient' else Booking.query.filter_by(therapist_id=user.id).all()
    return render_template("reports.html", bookings=bookings)

@app.route("/messages")
def messages():
    if "user_id" not in session: return redirect(url_for("login"))
    therapists = User.query.filter_by(role='therapist').all()
    patients = User.query.filter_by(role='patient').all()
    return render_template("messages.html", therapists=therapists, patients=patients)

@app.route("/schedule")
def schedule():
    if "user_id" not in session: return redirect(url_for("login"))
    user = User.query.get(session["user_id"])
    bookings = Booking.query.filter_by(patient_id=user.id).all()
    return render_template("schedule.html", bookings=bookings)

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))

# ----------------- RUN APP -----------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
