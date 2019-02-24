from flask import Flask, render_template, redirect, flash, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin
import json

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "bs"
db = SQLAlchemy()
login_manager = LoginManager()

db.init_app(app)
login_manager.init_app(app)

from werkzeug.security import generate_password_hash, check_password_hash






class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String, unique=True)
    password_hash = db.Column(db.String)
    
    @property
    def password(self):
        raise AttributeError("pass not readable")

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)


class Listing(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first = db.Column(db.String)
    last = db.Column(db.String)
    email = db.Column(db.String)
    price = db.Column(db.String)








from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField
from wtforms.validators import Required, Regexp, EqualTo

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[Required()])
    password = PasswordField("Password", validators=[Required()])
    remember_me = BooleanField("Keep me logged in")
    submit = SubmitField("Login")

class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[Required()])
    password = PasswordField("Password", validators=[Required()])
    confirm_password = PasswordField("Confirm password", validators=[Required(), EqualTo("password")])
    agree = BooleanField("I agree", validators=[Required()])
    submit = SubmitField("Register")







from flask_login import current_user, login_user, logout_user

@login_manager.user_loader
def loader_user(id):
    return User.query.get(int(id))

@app.route("/login", methods=["POST", "GET"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None or not user.verify_password(form.password.data):
            print("adssda")
            flash("invalid")
            return redirect("/login")
        login_user(user, remember=form.remember_me.data)
        return redirect("/")
    return render_template("login2.html", form=form)#, form=form)

@app.route("/register", methods=["POST", "GET"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        u = User(email=form.email.data, password=form.password.data)
        db.session.add(u)
        db.session.commit()
        return redirect("/")

    return render_template("register2.html", form=form)#), form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect("/")





@app.route("/")
def index():
    return render_template("home.html")#, users=User.query.all())


@app.route("/users")
def asdasddas():
    return " ".join(u.email for u in User.query.all())


@app.route("/search")
def se():
    return render_template("se.html")

@app.route('/index_get_data')
def stuff():
    try:

        d = json.load(open("MOCK_DATA.json"))
        data = {
            "data":d
        }
        return jsonify(data)

    except Exception as e:
        return jsonify({"data": [
          {
            "id": "1",
            "name": str(e),
            "position": "System Architect",
            "salary": "$320,800",
            "start_date": "2011/04/25",
            "office": "Edinburgh",
            "extn": "5421"
          },
      ]})








if __name__ == "__main__":
    app.run()