from flask import render_template, redirect, request, url_for, flash
from flask_login import login_user, logout_user, login_required
from ..email import send_email
from . import auth
from ..models import User
from .forms import LoginForm, RegistrationForm, ChangePwdForm, ForgetPwdForm, ResetPwdForm, ChangeEmailForm
from .. import db
from flask_login import current_user
import hashlib


@auth.before_app_request
def before_request():
    if current_user.is_authenticated:
        current_user.ping()
        if not current_user.confirmed \
                and request.endpoint[:5] != "auth." \
                and request.endpoint != "static":
            return redirect(url_for("auth.unconfirmed"))


@auth.route("/unconfirmed")
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for("main.index"))
    return render_template("auth/unconfirmed.html")


@auth.route("/change_pwd", methods=["GET", "POST"])
@login_required
def change_pwd():
    form = ChangePwdForm()
    if form.validate_on_submit():
        if (current_user.verify_password(form.password.data)):
            current_user.password = form.new_password.data
            db.session.add(current_user)
            flash("Success!! Your password is changed")
            return redirect(url_for("main.index"))
        else:
            flash("Defeat. Something is wrong.")
    return render_template("auth/change_pwd.html", form=form)


@auth.route("/change_email", methods=["GET", "POST"])
@login_required
def change_email():
    form = ChangeEmailForm()
    if form.validate_on_submit():
        token = current_user.generate_change_email_token()
        current_user.new_email = form.new_email.data
        send_email(current_user.new_email, "Change Your Email", "auth/email/change_email", user=current_user,
                   token=token)
        flash("Please checking on your new Email address")
        return redirect(url_for("main.index"))
    return render_template("auth/change_email.html", form=form)


@auth.route("/confirm_new_email/<token>", methods=["GET", "POST"])
@login_required
def confirm_new_email(token):
    if current_user.confirm_change_email(token):
        current_user.email = current_user.new_email
        current_user.avatar_hash = hashlib.md5(current_user.email.encode("utf-8")).hexdigest()
        db.session.add(current_user)
        flash("Your email is changed")
    else:
        flash("The confirmation link is invaild or has expired.")
    return redirect(url_for("main.index"))


@auth.route("/forget", methods=["GET", "POST"])
def forget():
    if not current_user.is_anonymous:
        return redirect(url_for("main.index"))
    form = ForgetPwdForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None:
            token = user.generate_reset_token()
            send_email(user.email, "Reset Your Password", "auth/email/reset_password", user=user, token=token)
            flash("Please checking on your Email address")
            return redirect(url_for("main.index"))
        else:
            flash("Your edited Email was wrong")
            return redirect(url_for("auth.forget"))
    return render_template("auth/forget.html", form=form)


@auth.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    if not current_user.is_anonymous:
        return url_for("main.index")
    form = ResetPwdForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user.confirm_reset(token):
            user.password = form.new_password.data
            db.session.add(user)
            flash("Success!! Your password has been reset")
        else:
            flash("The email your entered was wrong")
        return redirect(url_for("main.index"))
    return render_template("auth/reset_password.html", form=form)


@auth.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(request.args.get("next") or url_for("main.index"))
        flash("Invaild username or password.")
    return render_template("auth/login.html", form=form)


@auth.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out")
    return redirect(url_for("main.index"))


@auth.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data, username=form.username.data, password=form.password.data)
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token()
        send_email(user.email, "Confirm Your Account", "auth/email/confirm", user=user, token=token)
        flash("You can now login.")
        return redirect(url_for("main.index"))
    return render_template("auth/register.html", form=form)


@auth.route("/confirm")
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    send_email(current_user.email, "Confirm Your Account", "auth/email/confirm", user=current_user, token=token)
    flash("A new confirmation email has been sent to you by email")
    return redirect(url_for("main.index"))


@auth.route("/confirm/<token>")
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for("main.index"))
    if current_user.confirm(token):
        flash("You have confirmed your account. Thank!")
    else:
        flash("The confirmation link is invaild or has expired.")
    return redirect(url_for("main.index"))
