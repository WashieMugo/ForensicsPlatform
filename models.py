from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime


db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

class UploadedFile(db.Model):
    __tablename__ = 'uploaded_files'

    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(50), nullable=False)
    format = db.Column(db.String(50))
    size = db.Column(db.Integer)
    user_id = db.Column(db.Integer)
    upload_datetime = db.Column(db.DateTime, default=datetime.utcnow)  # Default to current time
    status = db.Column(db.String(50), default='Unscanned')

    # Updated constructor to exclude upload_datetime
    def __init__(self, filename, file_type, format=None, size=None, user_id=None):
        self.filename = filename
        self.file_type = file_type
        self.format = format
        self.size = size
        self.user_id = user_id
        # No explicit handling of upload_datetime, it's managed by SQLAlchemy

class AutoScan(db.Model):
    __tablename__ = 'autoscans'

    id = db.Column(db.Integer, primary_key=True)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    file_id = db.Column(db.Integer, db.ForeignKey('uploaded_files.id'), nullable=False)
    file_type = db.Column(db.String(50), nullable=False)
    report = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer) # Add user_id

    def __init__(self, start_time, end_time, file_id, file_type, report, user_id):
        self.start_time = start_time
        self.end_time = end_time
        self.file_id = file_id
        self.file_type = file_type
        self.report = report
        self.user_id = user_id  # Store user_id