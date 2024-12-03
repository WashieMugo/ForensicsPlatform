from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime


db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    
    # Add this relationship
    vol_manual = db.relationship('VolManual', back_populates='user')

class UploadedFile(db.Model):
    __tablename__ = 'uploaded_files'

    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(50), nullable=False)
    format = db.Column(db.String(50))
    size = db.Column(db.Integer)
    user_id = db.Column(db.Integer)
    upload_datetime = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default='Unscanned')
    doc_exists = db.Column(db.Boolean, default=False)
    has_metadata = db.Column(db.Boolean, default=False)
    metadata_file_path = db.Column(db.String, nullable=True)
    ftk_imaged = db.Column(db.Boolean, default=False)  # New column added

    # Relationship to FTKOps
    ftk_ops = db.relationship('FTKOps', backref='uploaded_file', lazy=True,
                            foreign_keys='FTKOps.file_id')
    # Relationship to VolManual
    vol_manual = db.relationship('VolManual', back_populates='file')

    def __init__(self, filename, file_type, format=None, size=None, user_id=None, ftk_imaged=False):
        self.filename = filename
        self.file_type = file_type
        self.format = format
        self.size = size
        self.user_id = user_id
        self.ftk_imaged = ftk_imaged  # Initialize the new field


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

# track File / Case Documentation 
class Documentation(db.Model):
    __tablename__ = 'documentation'

    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('uploaded_files.id'), nullable=False)
    case_number = db.Column(db.String(255), nullable=False)
    investigator_email = db.Column(db.String(255), nullable=False)
    purpose = db.Column(db.Text, nullable=False)
    option1 = db.Column(db.Boolean, default=False)
    option2 = db.Column(db.Boolean, default=False)
    option3 = db.Column(db.Boolean, default=False)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)

    def __init__(self, file_id, case_number, investigator_email, purpose, option1=False, option2=False, option3=False):
        self.file_id = file_id
        self.case_number = case_number
        self.investigator_email = investigator_email
        self.purpose = purpose
        self.option1 = option1
        self.option2 = option2
        self.option3 = option3
        self.last_updated = datetime.utcnow()

class FTKActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    operation = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class FTKOps(db.Model):
    __tablename__ = 'ftk_ops'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    file_id = db.Column(db.Integer, db.ForeignKey('uploaded_files.id'), nullable=False)
    hash_values = db.Column(db.Text)  # Store hash values as JSON string
    drive_info = db.Column(db.Text)   # Store drive information
    deleted_files = db.Column(db.Text) # Store deleted files information
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50))
    operation = db.Column(db.String(100))  # Add this field

    # Define relationships
    user = db.relationship('User', backref='ftk_ops')
    file = db.relationship('UploadedFile', backref='ftk_operations', 
                          foreign_keys=[file_id])

class VolManual(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    file_id = db.Column(db.Integer, db.ForeignKey('uploaded_files.id'), nullable=False)  # Corrected foreign key reference
    file_name = db.Column(db.String(255), nullable=False)
    date_time = db.Column(db.DateTime, default=datetime.utcnow)
    output = db.Column(db.String(255), nullable=False)

    user = db.relationship('User', back_populates='vol_manual')
    file = db.relationship('UploadedFile', back_populates='vol_manual')
