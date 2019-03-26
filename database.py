from flask_sqlalchemy import SQLAlchemy
from app import app
from sqlalchemy import Table, Column, Integer, ForeignKey

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    nombre_aleatoire = db.Column(db.Integer)
    version = db.Column(db.String(15))
    role = db.Column(db.String(50))
