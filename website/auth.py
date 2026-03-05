from flask import (
    Blueprint, render_template, request, flash,
    redirect, url_for
)
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user
import re

auth = Blueprint('auth', __name__)


def validate_password(pw: str) -> list[str]:
    """Return list of unmet password requirements (empty if OK)."""
    errors = []
    if len(pw) < 8:
        errors.append("at least 8 characters")
    if not re.search(r"[A-Z]", pw):
        errors.append("an uppercase letter")
    if not re.search(r"[a-z]", pw):
        errors.append("a lowercase letter")
    if not re.search(r"\d", pw):
        errors.append("a digit")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", pw):
        errors.append("a special character")
    return errors


@auth.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login with email and password authentication."""
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if not user:
            flash('Email does not exist.', category='error')
        elif not user.password:
            # password missing in database
            flash('Account invalid, please re-register.', category='error')
        elif check_password_hash(user.password, password):
            flash('Logged in successfully!', category='success')
            login_user(user, remember=True)
            return redirect(url_for('views.home'))
        else:
            flash('Incorrect password, try again.', category='error')
    data = request.form
    print(data)
    return render_template("login.html", user=current_user)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    """Handle user registration with email, name, and password validation."""
    if request.method == 'POST':
        email = request.form.get('email')
        firstName = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')
        elif not email or len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif not firstName or len(firstName) < 2:
            flash('First name must be greater than 1 character.', category='error')
        elif not password1 or not password2 or password1 != password2:
            flash('Passwords don\'t match.', category='error')
        else:
            problems = validate_password(password1)
            if problems:
                flash(
                    'Password must contain ' + ', '.join(problems) + '.',
                    category='error'
                )
            else:
                new_user = User(
                    email=email,
                    first_name=firstName,
                    password=generate_password_hash(password1, method='pbkdf2')
                )
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user, remember=True)
                flash('Account created!', category='success')
                return redirect(url_for('views.home'))

    return render_template("sign_up.html", user=current_user)