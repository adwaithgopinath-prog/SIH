from app import app, db, User
with app.app_context():
    users = User.query.limit(5).all()
    for u in users:
        print(f"Username: {u.username}, Password: {u.password}, Role: {u.role}")
