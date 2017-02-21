from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, Email, Regexp, EqualTo
from wtforms import ValidationError
from ..models import User


class ChangePwdForm(FlaskForm):
    password = PasswordField("Old password", validators=[DataRequired()])
    new_password = PasswordField("New password", validators=[DataRequired(),
                                                             EqualTo("new_password2",
                                                                     message="New passwords must match.")])
    new_password2 = PasswordField("Confirm new password", validators=[DataRequired()])
    submit = SubmitField("Update password")


class ChangeEmailForm(FlaskForm):
    new_email = StringField("New email", validators=[DataRequired(), Length(1, 64),
                                                     EqualTo("new_email2", message="New email must match"), Email()])
    new_email2 = StringField("Confirm new email", validators=[DataRequired(), Length(1, 64), Email()])
    submit = SubmitField("Submit")

    def validate_new_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError("Email already registered")


class ForgetPwdForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Length(1, 64), Email()])
    submit = SubmitField("Send email")


class ResetPwdForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Length(1, 64), Email()])
    new_password = PasswordField("New password", validators=[DataRequired(), EqualTo("new_password2",
                                                                                     message="New Passwords must match")])
    new_password2 = PasswordField("Confirm new password", validators=[DataRequired()])
    submit = SubmitField("Submit")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Length(1, 64), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    remember_me = BooleanField("Keep me logged in")
    submit = SubmitField("Log in")


class RegistrationForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Length(1, 64), Email()])
    username = StringField("Username", validators=[DataRequired(), Length(1, 64), Regexp("^[A-Za-z][A-Za-z0-9_.]*$", 0,
                                                                                         "Username must have only letters,"
                                                                                         "numbers,dots or underscores")])
    password = PasswordField("Password",
                             validators=[DataRequired(), EqualTo("password2", message="Passwords must match.")])
    password2 = PasswordField("Confirm password", validators=[DataRequired()])
    submit = SubmitField("Register")

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError("Email already registered")

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError("Username already in use.")
