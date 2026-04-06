import os
import sqlite3
from app import app, db, User, Booking
from datetime import datetime, timedelta

db_path = os.path.join('instance', 'sih.db')

# 1. Force delete the database file
try:
    if os.path.exists(db_path):
        os.remove(db_path)
        print(f"Successfully deleted {db_path}")
except Exception as e:
    print(f"Error deleting database: {e}")
    # If it's in use, we can't delete it while app.py is running.
    # But let's try to drop and recreate tables within the context instead.

with app.app_context():
    # 2. Drop all tables to be sure
    db.drop_all()
    # 3. Create all tables with the NEW schema
    db.create_all()
    print("Recreated all tables with fresh schema.")
    
    # 4. Seed new users
    patient = User(username='patient1', password='password123', role='patient')
    therapist = User(username='therapist1', password='password123', role='therapist')
    db.session.add(patient)
    db.session.add(therapist)
    db.session.commit()
    
    # 5. Add sample booking
    booking = Booking(
        patient_id=patient.id,
        therapist_id=therapist.id,
        start_time=datetime.now() + timedelta(days=1),
        end_time=datetime.now() + timedelta(days=1, hours=1),
        status='confirmed',
        notes='Initial Consultation'
    )
    db.session.add(booking)
    db.session.commit()
    print("Seeded test users and sample booking.")
