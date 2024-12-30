
from flask import render_template, redirect, url_for, flash, request
from flask_login import login_user, current_user, logout_user, login_required
from app import app, db, bcrypt
from models import User
from forms import RegistrationForm, LoginForm

@app.route("/")
@app.route("/home")
def home():
    return render_template('home.html')

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Account created successfully!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', form=form)


@app.route("/dashboard", methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        # Add a new user
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('User added successfully!', 'success')
        return redirect(url_for('dashboard'))


    # Fetch all users or filter by search term
    search = request.args.get('search', '')
    users = User.query.filter(
        (User.username.ilike(f'%{search}%')) |
        (User.email.ilike(f'%{search}%'))
    ).all()
    return render_template('dashboard.html', users=users)

@app.route("/update_user/<int:user_id>", methods=['POST'])
@login_required
def update_user(user_id):
    user = User.query.get_or_404(user_id)
    user.username = request.form.get('username', user.username)
    user.email = request.form.get('email', user.email)
    if 'password' in request.form and request.form.get('password'):
        hashed_password = bcrypt.generate_password_hash(request.form.get('password')).decode('utf-8')
        user.password = hashed_password
    db.session.commit()
    flash('User updated successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route("/delete_user/<int:user_id>", methods=['POST'])
@login_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully!', 'danger')
    return redirect(url_for('dashboard'))

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))
