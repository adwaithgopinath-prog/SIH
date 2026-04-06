from app import app, db, User, Booking
from datetime import datetime, timedelta

with app.app_context():
    # Recreate all tables
    db.create_all()
    
    # Only insert if empty
    if not User.query.filter_by(username='patient1').first():
        # Create users
        patient = User(username='patient1', password='password123', role='patient')
        therapist = User(username='therapist1', password='password123', role='therapist')
        
        db.session.add(patient)
        db.session.add(therapist)
        db.session.commit() # Commit to get IDs
        
        # Create a sample booking
        booking = Booking(
            patient_id=patient.id,
            therapist_id=therapist.id,
            start_time=datetime.now() + timedelta(days=1, hours=2),
            end_time=datetime.now() + timedelta(days=1, hours=3),
            status='confirmed',
            notes='Initial wellness consultation and Prakriti analysis.'
        )
        db.session.add(booking)
        db.session.commit()
        
        print(f"Created default users: patient1/password123 and therapist1/password123")
        print(f"Added sample booking for patient1 with therapist1")
    else:
        print("Users already exist in database.")
