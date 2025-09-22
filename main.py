from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ayursutra.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# -------------------- Models --------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='patient')  # patient/admin


class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    therapist_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending/confirmed/canceled
    notes = db.Column(db.String(300))

    patient = db.relationship('User', foreign_keys=[patient_id], backref='bookings')
    therapist = db.relationship('User', foreign_keys=[therapist_id])


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    content = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    sender = db.relationship('User', foreign_keys=[sender_id])
    receiver = db.relationship('User', foreign_keys=[receiver_id])


# -------------------- Login --------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# -------------------- Routes --------------------
@app.route('/')
def home():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('patient_dashboard'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/patient_dashboard')
@login_required
def patient_dashboard():
    # Example progress calculation
    total = Booking.query.filter_by(patient_id=current_user.id).count()
    completed = Booking.query.filter_by(patient_id=current_user.id, status='confirmed').count()
    progress_percent = int((completed / total) * 100) if total > 0 else 0
    return render_template('patient_dashboard.html', progress_percent=progress_percent)


@app.route('/book', methods=['GET', 'POST'])
@login_required
def book():
    if request.method == 'POST':
        start = datetime.strptime(request.form['start_time'], "%Y-%m-%dT%H:%M")
        end = datetime.strptime(request.form['end_time'], "%Y-%m-%dT%H:%M")
        new_booking = Booking(
            patient_id=current_user.id,
            start_time=start,
            end_time=end,
            status='pending',
            notes=request.form.get('notes')
        )
        db.session.add(new_booking)
        db.session.commit()
        flash("Booking requested successfully!")
        return redirect(url_for('schedule'))
    return render_template('book.html')


@app.route('/schedule')
@login_required
def schedule():
    bookings = Booking.query.filter_by(patient_id=current_user.id).all()
    return render_template('schedule.html', bookings=bookings, role='patient',
                           total_sessions=len(bookings),
                           upcoming_sessions=len([b for b in bookings if b.status == 'pending']),
                           completed_sessions=len([b for b in bookings if b.status == 'confirmed']),
                           canceled_sessions=len([b for b in bookings if b.status == 'canceled']))


@app.route('/messages')
@login_required
def messages():
    msgs = Message.query.filter_by(receiver_id=current_user.id).all()
    return render_template('messages.html', messages=msgs)


@app.route('/reports')
@login_required
def reports():
    bookings = Booking.query.filter_by(patient_id=current_user.id).all()
    return render_template('reports.html', bookings=bookings,
                           total_sessions=len(bookings),
                           upcoming_sessions=len([b for b in bookings if b.status == 'pending']),
                           completed_sessions=len([b for b in bookings if b.status == 'confirmed']),
                           canceled_sessions=len([b for b in bookings if b.status == 'canceled']))


# -------------------- Initialize DB and default user --------------------
def create_initial_user():
    if not User.query.filter_by(username="patient1").first():
        user = User(
            username="patient1",
            password=generate_password_hash("patientpass"),
            role='patient'
        )
        db.session.add(user)
        db.session.commit()


# -------------------- Run App --------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Ensure tables exist
        create_initial_user()  # Create default patient user

    app.run(debug=True)
