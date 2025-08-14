# handler.py
from run import app  # import the Flask app from run.py
from apig_wsgi import make_lambda_handler

lambda_handler = make_lambda_handler(app)