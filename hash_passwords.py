from app import app  # Import your Flask app instance
from models import db, User  # Adjust the import based on your project structure
from werkzeug.security import generate_password_hash

def hash_existing_passwords():
    """Hash plaintext passwords for all users and update the database."""
    with app.app_context():  # Ensure the Flask app context is active
        users = User.query.all()  # Fetch all users in the database
        for user in users:
            # Check if the password is already hashed
            if len(user.password) < 60:  # Assume plaintext passwords are shorter than 60 characters
                hashed_password = generate_password_hash(user.password)  # Use default 'pbkdf2:sha256'
                user.password = hashed_password
                print(f"Updated password for user: {user.username}")
        
        # Commit the changes to the database
        db.session.commit()
        print("All plaintext passwords have been hashed!")

if __name__ == "__main__":
    hash_existing_passwords()
