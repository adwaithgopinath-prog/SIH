from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)
app.secret_key = "supersecretkey"

# Database setup
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///sih.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


# ----------------- MODELS -----------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)


class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_name = db.Column(db.String(100), nullable=False)
    therapy_type = db.Column(db.String(100), nullable=False)
    date = db.Column(db.String(50), nullable=False)
    time = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ----------------- ROUTES -----------------
@app.route("/")
def home():
    # Landing page with "Get Started" button
    return render_template("dashboard.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(username=username, password=password).first()
        if user:
            session["user_id"] = user.id
            flash("Login successful!", "success")
            return redirect(url_for("patient_dashboard"))
        else:
            flash("Invalid username or password", "danger")
    return render_template("index.html")  # index.html is the login page


@app.route("/patient_dashboard")
def patient_dashboard():
    return render_template("patient_dashboard.html")


@app.route("/book", methods=["GET", "POST"])
def book():
    if request.method == "POST":
        patient_name = request.form["patient_name"]
        therapy_type = request.form["therapy_type"]
        date = request.form["date"]
        time = request.form["time"]

        new_booking = Booking(
            patient_name=patient_name, therapy_type=therapy_type, date=date, time=time
        )
        db.session.add(new_booking)
        db.session.commit()

        flash("Booking successful!", "success")
        return redirect(url_for("book"))

    return render_template("book.html")


@app.route("/reports")
def reports():
    return render_template("reports.html")


@app.route("/messages")
def messages():
    return render_template("messages.html")


@app.route("/schedule")
def schedule():
    return render_template("schedule.html")


# ----------------- RUN APP -----------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
