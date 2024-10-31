from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Length, EqualTo
from flask_wtf.file import FileField, FileRequired, FileAllowed

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=150)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class UploadFileForm(FlaskForm):
    file = FileField('Select File', validators=[
        FileRequired(),
        FileAllowed(['mem', 'dmp', 'raw', 'lks', 'hdd', 'iso', 'img', 'dd', 'e01'], 'Memory and Image files only!')
    ])
    submit = SubmitField('Upload')

# FTK Imager: 
class FTKOperationsForm(FlaskForm):
    operation = SelectField(
        'Select Operation',
        choices=[
            ('create_disk_image', 'Create Disk Image'),
            ('extract_files', 'Extract Files'),
            ('hash_files', 'Generate Hash of Files')
        ]
    )
    submit = SubmitField('Run Operation')