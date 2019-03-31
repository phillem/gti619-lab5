from flask_sqlalchemy import SQLAlchemy
from flask import Flask
from sqlalchemy import Table, Column, Integer, ForeignKey

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    nombre_aleatoire = db.Column(db.Integer)
    role = db.Column(db.String(50))

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id

    def get_role(self):
        return self.role

    def __repr__(self):
        return '<User %r>' % (self.username)


class SecurityParameters(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    failedAttemptsMax = db.Column(db.Integer)
    pwCapitalAmount = db.Column(db.Integer)
    pwNumberAmount = db.Column(db.Integer)
    pwSpecialCharacterAmount = db.Column(db.Integer)
    passwordMin = db.Column(db.Integer)
    passwordMax = db.Column(db.Integer)
    usernameMin = db.Column(db.Integer)
    usernameMax = db.Column(db.Integer)

