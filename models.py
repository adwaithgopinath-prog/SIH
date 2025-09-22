from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # patient / therapist / admin

    # Relationships
    patient_bookings = db.relationship(
        'Booking', foreign_keys='Booking.patient_id', backref='patient', lazy=True
    )
    therapist_bookings = db.relationship(
        'Booking', foreign_keys='Booking.therapist_id', backref='therapist', lazy=True
    )

    def __repr__(self):
        return f"<User {self.username} ({self.role})>"


class Booking(db.Model):
    __tablename__ = "booking"

    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    therapist_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default="pending")  # pending / confirmed / canceled
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.Column(db.Text, nullable=True)  # optional notes for the session

    def __repr__(self):
        return (
            f"<Booking {self.id}: patient {self.patient_id}, "
            f"therapist {self.therapist_id}, {self.start_time}>"
        )
