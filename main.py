from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users_data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
#Line below only required once, when creating DB. 
# db.create_all()


@app.route('/')
def home():
    return render_template("index.html", logged_in=current_user.is_authenticated)


@app.route('/register', methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        user = User.query.filter_by(email=request.form.get("email")).first()
        if not user:
            new_user = User(
                email=request.form.get("email"),
                password=generate_password_hash(password=request.form.get("password"), method="pbkdf2:sha256", salt_length=8),
                name=request.form.get("name")
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for("secrets"))
        else:
            error = "You have already signed up with that email. Please log in instead."
            return render_template("login.html", error=error)
    return render_template("register.html", logged_in=current_user.is_authenticated)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/login', methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        login_email = request.form.get("email")
        login_password = request.form.get("password")
        user = User.query.filter_by(email=login_email).first()
        if user:
            if check_password_hash(user.password, login_password):
                login_user(user)
                flash("You were successfully logged in.")
                return redirect(url_for("secrets"))
            else:
                error = "Invalid password."
        else:
            error = "That email does not exist."
    return render_template("login.html", error=error, logged_in=current_user.is_authenticated)


@app.route('/secrets')
@login_required
def secrets():
    print(current_user.name)
    return render_template("secrets.html", name=current_user.name, logged_in=True)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for("home"))


@app.route('/download')
@login_required
def download():
    return send_from_directory(directory="static/files", filename="information.pdf")


if __name__ == "__main__":
    app.run(debug=True)
