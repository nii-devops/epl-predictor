from flask_sqlalchemy import SQLAlchemy

#db = SQLAlchemy()

from flask_login import UserMixin
from app import db  


# User Model
class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    nickname = db.Column(db.String(30) )
    username = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120))

    is_admin = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<User {self.username}>'


# Week Model
class Week(db.Model):
    __tablename__ = 'weeks'  # Define table name
    id          = db.Column(db.Integer, primary_key=True)
    week_number = db.Column(db.Integer, unique=True, nullable=False)
    


# Fixture Model
class Fixture(db.Model):
    __tablename__ = 'fixtures'  # Define table name
    id          = db.Column(db.Integer, primary_key=True)
    week_id     = db.Column(db.Integer, db.ForeignKey('weeks.id'), nullable=False)
    matches     = db.Column(db.JSON, nullable=False)
    
    # Establishing relationships
    week        = db.relationship('Week', backref='fixture')



# Prediction Model
class Prediction(db.Model):
    __tablename__ = 'predictions'  # Define table name
    id                  = db.Column(db.Integer, primary_key=True)
    user_id             = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    week_id             = db.Column(db.Integer, db.ForeignKey('weeks.id'), nullable=False)
    user_predictions    = db.Column(db.JSON, nullable=False)
    
    # Establishing relationships
    user                = db.relationship('User', backref='prediction')
    week                = db.relationship('Week', backref='prediction')



# Prediction Model
class Result(db.Model):
    __tablename__ = 'results'  # Define table name
    id      = db.Column(db.Integer, primary_key=True)
    week_id = db.Column(db.Integer, db.ForeignKey('weeks.id'), nullable=False)
    results = db.Column(db.JSON, nullable=False)
    
    # Establishing relationships
    week    = db.relationship('Week', backref='result')



# Score Model
class Score(db.Model):
    __tablename__ = 'scores'  # Define table name
    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    week_id     = db.Column(db.Integer, db.ForeignKey('weeks.id'), nullable=False)
    points      = db.Column(db.Integer, default=0)

    # Relationships
    user        = db.relationship('User', backref='score')
    week        = db.relationship('Week', backref='score')


# Score Model
class Xrecord(db.Model):
    __tablename__ = 'xrecords'  # Define table name
    
    id          = db.Column(db.Integer, primary_key=True)
    name     = db.Column(db.String, nullable=False)
    points      = db.Column(db.Integer, default=0)









