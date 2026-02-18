from flask import Flask, render_template, request, redirect, session, flash
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import re

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.secret_key = 'secret_key'

db = SQLAlchemy(app)


# ------------------ MODEL ------------------ #
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    def __init__(self, name, email, password):
        self.name = name
        self.email = email
        self.password = bcrypt.hashpw(
            password.encode('utf-8'),
            bcrypt.gensalt()
        ).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(
            password.encode('utf-8'),
            self.password.encode('utf-8')
        )


with app.app_context():
    db.create_all()


# ------------------ HOME ------------------ #
@app.route('/')
def home():
    return render_template('index.html')


# ------------------ REGISTER (VALIDATION FIXED) ------------------ #
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':

        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        # 1️⃣ Name validation
        if not name:
            flash("Name should not be empty.", "danger")
            return redirect('/register')

        # 2️⃣ Email validation
        if not email:
            flash("Email should not be empty.", "danger")
            return redirect('/register')

        # Email format validation
        email_pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        if not re.match(email_pattern, email):
            flash("Invalid email format.", "danger")
            return redirect('/register')

        # 3️⃣ Password validation
        if not password:
            flash("Password should not be empty.", "danger")
            return redirect('/register')

        # 5️⃣ Password length validation
        if len(password) < 6:
            flash("Password must be at least 6 characters.", "danger")
            return redirect('/register')

        # 4️⃣ Email uniqueness validation
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Email already registered.", "danger")
            return redirect('/register')

        # ✅ Create user if all validations pass
        new_user = User(name=name, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful! Please login.", "success")
        return redirect('/login')

    return render_template("register.html")


# ------------------ LOGIN ------------------ #
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':

        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        if not email or not password:
            flash("Both fields are required.", "danger")
            return redirect('/login')

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            session['email'] = user.email
            return redirect('/dashboard')
        else:
            flash("Invalid email or password.", "danger")
            return redirect('/login')

    return render_template("login.html")


# ------------------ DASHBOARD ------------------ #
@app.route('/dashboard')
def dashboard():
    if 'email' not in session:
        return redirect('/login')

    return render_template('dashboard.html')


# ------------------ LOGOUT ------------------ #
@app.route('/logout')
def logout():
    session.pop('email', None)
    return redirect('/login')


if __name__ == '__main__':
    app.run(debug=True)
