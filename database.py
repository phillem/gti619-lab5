from flask_sqlalchemy import SQLAlchemy
from app import app
from sqlalchemy import Table, Column, Integer, ForeignKey
from datetime import datetime

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    nombre_aleatoire = db.Column(db.Integer)
    role = db.Column(db.String(50))


class Connection_log(db.Model):
    authenticationId = db.Column(db.Integer, primary_key=True)
    userId = db.Column(db.Integer, db.ForeignKey('user.id'),
                       nullable=False)
    user = db.relationship('User',
                               backref=db.backref('connection', lazy=True))
    time_connection = db.Column(db.DateTime, nullable=False,
                                default=datetime.utcnow)
    is_succesful = db.Column(db.Boolean)
