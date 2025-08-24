from flask import Flask 
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from authlib.integrations.flask_client import OAuth
import os
from flask_bootstrap import Bootstrap5
from datetime import timedelta
from flask_mail import Mail
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from dotenv import load_dotenv


load_dotenv()

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()
migrate = Migrate()
oauth = OAuth()
mail = Mail()

ADMINS = ['niiakoadjei@gmail.com','techwavegh@gmail.com','isaackusiantwi@gmail.com']

TOKEN_SALT = 'password-reset-salt'


# ItsDangerous serializer for tokens
s = URLSafeTimedSerializer(secret_key=os.getenv('SECRET_KEY', 'yourvnsh7532f8y7tcajj,_87gvtftftfcret-key-here'))

def create_app():
    app = Flask(__name__)

    # BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    # SQLALCHEMY_DATABASE_URI = f"sqlite:///{os.path.join(BASE_DIR, 'mydb.db')}"
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'yourvnsh7532f8y7tcajj,_87gvtftftfcret-key-here')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLITE_DB_URI', 'sqlite:///epl_predictions.db')
    #app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'postgresql://niiakoadjei:HelveticaSwift86@localhost:5432/eplprediction_db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID')
    app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET')

    app.permanent_session_lifetime = timedelta(minutes=30)

    # Initialize extensions with app
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    login_manager.login_view = 'main.login'
    oauth.init_app(app)
    Bootstrap5(app)

    # IMPORTANT: Import models AFTER db.init_app() but BEFORE register_blueprint
    from . import models

    # Google OAuth registration
    google = oauth.register(
        name='google',
        client_id=app.config['GOOGLE_CLIENT_ID'],
        client_secret=app.config['GOOGLE_CLIENT_SECRET'],
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={
            'scope': 'openid email profile'
        }
    )

    #############################
    # Flask-Mail Configuration
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USER')
    app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASS')

    # ItsDangerous serializer for tokens
    #app.token_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    #s.secret_key = app.config['SECRET_KEY']

    mail.init_app(app)

    
    # User loader
    @login_manager.user_loader
    def load_user(user_id):
        return models.User.query.get(int(user_id))

    # Register blueprints
    from .routes import bp as main_bp
    app.register_blueprint(main_bp)

    with app.app_context():
        # Create tables if they don't exist
        db.create_all()

    return app

