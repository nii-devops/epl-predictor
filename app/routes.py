from flask import Flask, render_template, redirect, url_for, flash, session, request, message_flashed
from flask_login import current_user, login_user, logout_user, login_required, LoginManager
from .forms import (RegisterForm, LoginForm, DatabaseForm, FixtureForm, ResultsForm, PredictionForm, 
                    NameForm, SelectWeekForm, PredictionWeekForm, UserEmailForm, PredictResultWeekForm,
                    UserPredictionForm, ScoreWeekForm, NickNameForm)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from . import db, app, login_manager
from .models import User, Week, Fixture, Score, Result, Prediction
from pprint import pprint
from sqlalchemy import inspect, text
from authlib.integrations.flask_client import OAuth
import os
from flask_bootstrap import Bootstrap5




Bootstrap5(app)

teams_names = {
    'ARS': 'Arsenal', 
    'AST': 'Aston Villa', 
    'BOU': 'Bournemouth', 
    'BRE': 'Brentford', 
    'BRI': 'Brighton', 
    'CHE': 'Chelsea', 
    'CRY': 'Crystal Palace', 
    'EVE': 'Everton', 
    'FUL': 'Fulham', 
    'IPS': 'Ipswich Town', 
    'LEI': 'Leicester City', 
    'LIV': 'Liverpool', 
    'MNC': 'Manchester City', 
    'MNU': 'Manchester United', 
    'NEW': 'Newcastle', 
    'NFO': 'Nottingham Forest', 
    'SOU': 'Southampton', 
    'TOT': 'Tottenham', 
    'WES': 'West Ham', 
    'WOL': 'Wolves'
    }


login_manager = LoginManager()
login_manager.init_app(app)

def reverse_team_names():
    reversed_names = {}
    for i,j in teams_names.items():
        reversed_names[j] = i
    return reversed_names 


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.before_request  # Use before_request to apply to the entire app
def session_management():
    session.permanent = True  # Set the session as permanent
    session.modified = True   # Update session with each request

    # If the user is logged in, check session expiry
    if current_user.is_authenticated:
        if 'last_activity' in session:
            # Ensure last_activity is timezone-aware
            last_activity = session['last_activity'].replace(tzinfo=datetime.now().tzinfo)
            idle_time = timedelta(minutes=10)  # Idle time limit
            if datetime.now() - last_activity > idle_time:
                # If idle time exceeded, log out user and clear session
                logout_user()
                session.clear()
                return redirect(url_for('login'))  # Redirect to login page

        # Update last activity time if session is still active
        session['last_activity'] = datetime.now()  # This will be timezone-aware




oauth = OAuth(app)

google = oauth.register(
    name='google',
    client_id=os.getenv('CLIENT_ID'),
    client_secret=os.getenv('CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid profile email'}
)


# #############################
# #### ROUTES ROUTES ROUTES ###

@app.route('/')
def home():
    return render_template('index.html', title='Home')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        
        name = form.name.data
        nickname = form.nickname.data
        username = form.username.data
        password = form.password.data
        hashed_passwd = generate_password_hash(password=password, method='scrypt', salt_length=16)

        usr = User.query.filter_by(username=form.username.data).first()
        if not usr:
            # Save user data to database
            user = User(
                name=name,
                nickname=nickname,
                username=username,
                password=hashed_passwd
                )
            db.session.add(user)
            db.session.commit()

            # Query database for user...
            user = User.query.filter_by(username=form.username.data).first()
            if user:
                login_user(user)
                flash(f'Welcome, {name}.', category='success')
                return redirect(url_for('home'))
            else:
                flash(f'Accrount creation for {username} failed!', category='danger')
        else:
            flash(f'Username {username} already exists.', category='danger')
        
    return render_template('register.html', title='Register', form=form)



@app.route('/login', methods=['GET','POST'])
def login():
    # Check if the user is already authenticated
    if current_user.is_authenticated:
        flash('User is already authenticated.', 'info')
        return redirect(url_for('profile', username=current_user.username))  # Redirect to profile page
    
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        user = User.query.filter_by(username=username).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                flash("Login successful!", 'success')
                return redirect(url_for('profile', user_id=user.id))  # Redirect to profile page
            flash("Password incorrect! Try again", 'warning')
        flash(f"User with email {username} does not exist! Try again or register.", 'danger')
    return render_template('login.html', title='Login', form=form)




# New route for the profile page
@app.route('/profile/<int:user_id>')
@login_required
def profile(user_id):
    my_user = User.query.filter_by(id=user_id).first_or_404()
    scores = []
    points = 0
    position = None
    rank_id = None
    users = User.query.all()
    for user in users:
        score = sum(score.points for score in Score.query.filter_by(user_id=user.id).all())
        item = {user.id: score}
        scores.append(item)
    sorted_scores = sorted(scores, key=lambda x: list(x.values())[0], reverse=True)
    
    for i,j in enumerate(sorted_scores):
        for key,val in j.items():
            if int(key) == user_id:
                points = val
                rank_id = i+1
    if str(rank_id)[-1] == '1':
        position = f"{rank_id}st"
    elif str(rank_id)[-1] == '2':
        position = f"{rank_id}nd"
    elif str(rank_id)[-1] == '3':
        position = f"{rank_id}rd"
    else:
        position = f"{rank_id}th"

    return render_template('profile.html', title='Profile', user=my_user, position=position, points=points)





@app.route('/login/google')
def google_login():
    try:
        # Explicitly set the redirect URI
        redirect_uri = os.getenv('REDIRECT_URI')
        
        app.logger.info(f"Using redirect URI: {redirect_uri}")
        
        return google.authorize_redirect(redirect_uri)
    except Exception as e:
        app.logger.error(f"Login Error: {str(e)}")
        return "Error occurred during login!"



@app.route('/authorize/google')
def authorize_google():
    try:
        # Exchange the authorization code for a token
        token = google.authorize_access_token()
        
        # Fetch user information from Google's user info endpoint
        userinfo_endpoint = google.server_metadata.get('userinfo_endpoint')
        if not userinfo_endpoint:
            raise ValueError("User info endpoint not found in Google metadata.")
        
        resp = google.get(userinfo_endpoint)
        user_info = resp.json()  # Use .json() to parse the response correctly
        
        # Extract user details
        username = user_info.get('email')
        name = user_info.get('name')

        if not username:
            raise ValueError("Email not found in user information.")

        # Check if user exists or create a new one
        user = User.query.filter_by(username=username).first()

        if not user:
            session['username'] = username
            session['name'] = name
            session['oauth_token'] = token
            return redirect(url_for('nickname', username=username, name=name))
        else:
            name = user.name
            login_user(user)
            flash(f'Welcome, {name}.', 'success')
            return redirect(url_for('home'))

    except Exception as e:
        app.logger.error(f"Authorization Error: {str(e)}")
        return "Error occurred during authorization!"



# LOCALHOST CONFIGURATION
"""
# Login for Google
@app.route('/login/google')
def google_login():
    try:
        redirect_uri = url_for('authorize_google', _external=True)
        return google.authorize_redirect(redirect_uri)
    except Exception as e:
        app.logger.error(f"Login Error: {str(e)}")
        return "Error occurred during login!"


# Authorize for Google
@app.route('/authorize/google')
def authorize_google():
    try:
        token = google.authorize_access_token()
        userinfo_endpoint = google.server_metadata.get('userinfo_endpoint')
        if not userinfo_endpoint:
            raise ValueError("User info endpoint not found in Google metadata.")
        
        resp = google.get(userinfo_endpoint)
        user_info = resp.json()  # use .json() to parse the response correctly
        username = user_info.get('email')
        name = user_info.get('name')

        if not username:
            raise ValueError("Email not found in user information.")

        # Check if user exists or create a new one
        user = User.query.filter_by(username=username).first()

        if not user:
            session['username'] = username
            session['name'] = name
            session['oauth_token'] = token
            return redirect(url_for('nickname', username=username, name=name))
        else:
            name = user.name
            login_user(user)
            flash(f'Welcome, {name}.', 'success')
            return redirect(url_for('home'))

    except Exception as e:
        app.logger.error(f"Authorization Error: {str(e)}")
        return "Error occurred during authorization!"



"""



@app.route('/nickname', methods=['GET', 'POST'])
def nickname():
    form = NickNameForm()
    username = request.args.get('username')
    name = request.args.get('name')
    form.username.data = username
    form.name.data =  name

    if form.validate_on_submit():
        nickname = form.nickname.data
        name = form.name.data
        new_user = User(
            username=username,
            nickname=nickname,
            name=name
        )
        db.session.add(new_user)
        db.session.commit()
        user = User.query.filter_by(username=username).first()
        if user:
            login_user(user)
            flash(f"Welcome, {name}.", "success")
            return redirect(url_for('profile', user_id=user.id))
        else:
            flash("User not found", 'danger')
    return render_template('nickname.html', title='Set Nickname', form=form)



@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    flash(f"User logged out successfully.", 'success')
    return redirect(url_for('home'))



@app.route('/select-matchweek', methods=['GET', 'POST'])
def match_week():
    form = SelectWeekForm()

    if form.validate_on_submit():

        week_number = form.week.data
        # Ensure week_number is an integer
        try:
            week_number = int(week_number)  # Convert to integer
        except ValueError:
            flash("Invalid week number!", category='warning')
            return render_template('match_week.html', title='Select Week', form=form)

        # Check if the week_number already exists
        if not Week.query.filter_by(week_number=week_number).first():
            week = Week(
                week_number=week_number
            )
            db.session.add(week)
            db.session.commit()  # Define message
            flash(f'Week {week_number} created successfully!', 'success')
            return redirect(url_for('fixtures'))
        else:
            flash(f'Week {week_number} already exists!', 'warning')
    else:
        message = None  # Define message as None if form is not submitted
    return render_template('match_week.html', title='Select Week', form=form)  # Pass message to template




@app.route('/fixture', methods=['GET', 'POST'])
def fixtures():
    form = FixtureForm()
    
    weeks = Week.query.order_by(Week.week_number).all()  # Retrieve week numbers
    if weeks:
        form.game_week.data = max(week.week_number for week in weeks)
    #form.game_week.choices = [(week.week_number, f"Week {week.week_number}") for week in weeks]

    if form.validate_on_submit():  # Check if the form is submitted and valid
        week = form.game_week.data
        # Ensure week is an integer
        try:
            week = int(week)  # Convert to integer
        except ValueError:
            flash("Invalid week selection!", category='warning')
            return render_template('fixtures.html', title='Home', form=form)

        fixture_data = {
            "match_1": f"{form.home_1.data}-{form.away_1.data}",
            "match_2": f"{form.home_2.data}-{form.away_2.data}",
            "match_3": f"{form.home_3.data}-{form.away_3.data}",
            "match_4": f"{form.home_4.data}-{form.away_4.data}",
            "match_5": f"{form.home_5.data}-{form.away_5.data}",
            "match_6": f"{form.home_6.data}-{form.away_6.data}",
            "match_7": f"{form.home_7.data}-{form.away_7.data}",
            "match_8": f"{form.home_8.data}-{form.away_8.data}",
            "match_9": f"{form.home_9.data}-{form.away_9.data}",
            "match_10": f"{form.home_10.data}-{form.away_10.data}",
        }
        # Check if the fixture already exists for the given week_id
        existing_fixture = Fixture.query.filter_by(week_id=week).first()
        if existing_fixture:
            flash(f'Fixtures for week {week} already exist!', 'warning')
            return redirect(url_for('home'))  # Redirect if it exists

        new_fixture = Fixture(
            week_id=week,
            matches=fixture_data
        )  # Create a new Fixture instance
        db.session.add(new_fixture)  # Add to the session
        db.session.commit()  # Commit the session
        
        flash(f'Week {week} fixtures created successfully!', 'success')  # Flash a success message
        return redirect(url_for('home'))  # Redirect to the fixtures page
    return render_template('fixtures.html', title='Create Fixture', form=form)




@app.route('/predict', methods=['GET', 'POST'])
@login_required
def predict():
    form = PredictionForm()

    weeks = Week.query.order_by(Week.week_number).all()  # Retrieve week numbers
    if weeks:
        form.game_week.data = max(week.week_number for week in weeks)

    week = form.game_week.data
    try:
        week = int(week)  # Convert to integer if possible
    except (TypeError, ValueError):
        flash("Invalid week number provided!", category='danger')
        return redirect(url_for('prediction_week'))

    # Create empty lists for home and away teams
    home_teams = []
    away_teams = []

    # Query the Fixture table for the specified week
    fixture_data = Fixture.query.filter_by(week_id=week).first()
    if fixture_data:
        data = fixture_data.matches
        for key, val in data.items():
            home, away = val.split('-')
            home_teams.append(home)
            away_teams.append(away)

        # Populate the form with home and away teams
        for i in range(len(home_teams)):
            if i < 10:  # Ensure we don't exceed the form fields
                form[f'home_{i + 1}'].data = home_teams[i]
                form[f'away_{i + 1}'].data = away_teams[i]

    # When form is submitted
    if form.validate_on_submit():
        game_week = week
        prediction_data = {}
        for i in range(1, 11):  # Iterate from 1 to 10 to populate predicted scores into a JSON-formatted text
            prediction_data[f"{form[f'home_{i}'].data}-{form[f'away_{i}'].data}"] = {
                "home": f"{form[f'home_{i}_score'].data}",
                "away": f"{form[f'away_{i}_score'].data}"
            }
        # Write/Save data to database
        prediction = Prediction(
            week_id             = game_week,
            user_id             = current_user.id,
            user_predictions    = prediction_data
        )
        db.session.add(prediction)
        db.session.commit()
        flash(f"Predictions for Game Week {game_week} submitted.", 'success')
        return redirect(url_for('home'))
    return render_template('predict.html', title='Predict Results', form=form, week=week)




@app.route('/results', methods=['GET', 'POST'])
# @login_required
def results():
    form = PredictionForm()

    weeks = Week.query.order_by(Week.week_number).all()  # Retrieve week numbers
    if weeks:  # Check if there are any weeks
        form.game_week.data = max(week.week_number for week in weeks)  # Set the highest week_number

    # Get and validate the week parameter
    week = form.game_week.data

    try:
        week = int(week)  # Convert to integer if possible
    except (TypeError, ValueError):
        flash("Invalid week number provided!", category='danger')
        return redirect(url_for('prediction_week'))

    # Create empty lists for home and away teams
    home_teams = []
    away_teams = []

    # Query the Fixture table for the specified week
    fixture_data = Fixture.query.filter_by(week_id=week).first()
    if fixture_data:
        data = fixture_data.matches
        for key, val in data.items():
            home, away = val.split('-')
            home_teams.append(home)
            away_teams.append(away)

        # Populate the form with home and away teams
        for i in range(len(home_teams)):
            if i < 10:  # Ensure we don't exceed the form fields
                form[f'home_{i + 1}'].data = home_teams[i]
                form[f'away_{i + 1}'].data = away_teams[i]

    if form.validate_on_submit():
        game_week = form.game_week.data
        results_data = {}
        for i in range(1, 11):  # Iterate from 1 to 10 to populate predicted scores into a JSON-formatted text
            results_data[f"{form[f'home_{i}'].data}-{form[f'away_{i}'].data}"] = {
                "home": f"{form[f'home_{i}_score'].data}",
                "away": f"{form[f'away_{i}_score'].data}"
            }
        # Write/Save data to database
        results = Result(
            week_id = game_week,
            results = results_data
        )
        db.session.add(results)
        db.session.commit()
        flash(f"Results for Game Week {game_week} submitted.", 'success')
        score()
        return redirect(url_for('home'))

    return render_template('results.html', title='Enter Results', form=form, week=week)




@app.route('/show-fixtures', methods=['GET' ,'POST'])
def get_fixtures():
    form = SelectWeekForm()
    keys = []
    matches = []
    if form.validate_on_submit():
        wk = form.week.data
        fixture_data = Fixture.query.filter_by(week_id=wk).first()
        if fixture_data:
            data = fixture_data.matches
            print(data)
            for key, val in data.items():
                matches.append(val)
            return render_template('get_fixtures.html', keys=keys, matches=matches, week=wk)  # Return the JSON response

    return render_template('get_fixtures.html', title='Test Data', form=form)




@app.route('/get-user-data', methods=['GET' ,'POST'])
def get_user():
    form = UserEmailForm()
    
    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()

        if user:
            user_id = user.id
            name = user.name
            user_email = user.email
            return render_template('get_user.html', id=user_id, name=name, email=user_email)  # Return the JSON response

    return render_template('get_user.html', title='Find User', form=form)



@app.route('/get-user-predictions', methods=['GET' ,'POST'])
def get_user_predictions():
    form = UserPredictionForm()  
    weeks = Week.query.order_by(Week.week_number).all()  # Retrieve week numbers
    form.week.choices = [(week.week_number, f"Week {week.week_number}") for week in weeks]

    if form.validate_on_submit():
        week = form.week.data
        email = form.email.data

        try:
            week = int(week)  # Convert to integer if possible
        except (TypeError, ValueError):
            flash("Invalid week number provided!", category='danger')
            return redirect(url_for('get_predictions'))
        user = User.query.filter_by(email=email).first()
        user_prediction = Prediction.query.filter_by(user_id=user.id, week_id=week).first()
        data = user_prediction.user_predictions
        matches = {}
        if user_prediction:
            user_id = user.id
            name = user.name
            user_email = user.email
            num = 1
            for key,val in data.items():
                ht,at = key.split("-")
                matches[f"Match {num}"] = {
                        ht: val["home"],
                        at: val["away"]
                    }
                num += 1
            print(matches)
            return render_template('get_user_predictions.html', id=user_id, name=name, week=week, matches=matches)  # Return the JSON response

    return render_template('get_user_predictions.html', title='User Predictions', form=form)



@app.route('/get-predictions', methods=['GET' ,'POST'])
def get_predictions():
    form = SelectWeekForm() 
    weeks = Week.query.order_by(Week.week_number).all()  # Retrieve week numbers
    form.week.choices = [(week.week_number, f"Week {week.week_number}") for week in weeks]

    # New code to set the highest week_number in the form
    if weeks:  # Check if there are any weeks
        form.week.data = max(week.week_number for week in weeks)  # Set the highest week_number

    if form.validate_on_submit():
        week = form.week.data

        try:
            week = int(week)  # Convert to integer if possible
        except (TypeError, ValueError):
            flash("Invalid week number provided!", category='danger')
            return redirect(url_for('get_predictions'))
        
        team_names = reverse_team_names()

        match_list = ["Name"]
        match_data = Fixture.query.filter_by(week_id=week).first()
        matches = match_data.matches
  
        for key, val in matches.items():
            h_team, a_team = val.split("-")
            h_team = team_names[h_team]
            a_team = team_names[a_team]
            match_list.append(f"{h_team}-{a_team}")

        full_scores = {}
        print(full_scores)

        users_data = User.query.order_by(User.name).all()
        for user in users_data:
            user_pred = Prediction.query.filter_by(week_id=week, user_id=user.id)#.first()
            if user_pred and week == 1:  # Check if user predictions exist
                name = user.name
                user_scores = []  # Ensure this is initialized as a list
                for key, val in user_pred[0].user_predictions.items():
                    home_team, away_team = key.split("-")
                    home_team = team_names[home_team]
                    away_team = team_names[away_team]
                    score = f"{val['home']}-{val['away']}"
                    user_scores.append(score)  # Ensure scores are appended correctly
                # Clear user_scores only after processing all predictions for the user
                full_scores[name] = user_scores  # This should work as intended
        print(full_scores)
        return render_template('get_predictions.html', matches=match_list, scores=full_scores, week=week)

    return render_template('get_predictions.html', form=form)  # Pass predictions to the template




@app.route('/get-results', methods=['GET' ,'POST'])
def get_results():
    form = SelectWeekForm()
    
    weeks = Week.query.order_by(Week.week_number).all()  # Retrieve week numbers
    form.week.choices = [(week.week_number, f"Week {week.week_number}") for week in weeks]

    if form.validate_on_submit():
        week = form.week.data
        
        try:
            week = int(week)  # Convert to integer if possible
        except (TypeError, ValueError):
            flash("Invalid week number provided!", category='danger')
            return redirect(url_for('get_predictions'))

        match_results = Result.query.filter_by(week_id=week).first()
        data = match_results.matches
        results = {}
        if match_results:
            num = 1
            for key,val in data.items():
                ht,at = key.split("-")
                results[f"Match {num}"] = {
                        ht: val["home"],
                        at: val["away"]
                    }
                num += 1
            print(results)
            return render_template('get_results.html', week=week, results=results)  # Return the JSON response

    return render_template('get_results.html', title='Weekly Results', form=form)





@app.route('/generate-scores', methods=['GET' ,'POST'])
def score():

    weeks = Week.query.order_by(Week.week_number).all()  # Retrieve week numbers
    if weeks:
        week = max(week.week_number for week in weeks)

    try:
        week = int(week)  # Convert to integer if possible
    except (TypeError, ValueError):
        flash("Invalid week number provided!", category='danger')
        return redirect(url_for('get_predictions'))
        
    #Check if the selected week's score already exists
    if Score.query.filter_by(week_id=week).first():
        flash(f"Week {week} scores exist axist!")

    week_results = Result.query.filter_by(week_id=week).first()
    # Organize result into json
    results     = {"master": week_results.results}    
    # New code to convert user_predictions to a list of dictionaries
    user_predictions = Prediction.query.filter_by(week_id=week).all()  # Get all user predictions for the week

    # Compare user predictions with results and assign scores
    for prediction in user_predictions:
        user_score = prediction.user_predictions
        match_results = results["master"]  # Access the results
        user_points = 0
        print(user_points)
        for match, score in user_score.items():
            # Check if the match exists in the results
            if match in match_results:
                # Compare scores and assign points
                if match_results[match]["home"] == score["home"] and match_results[match]["away"] == score["away"]:
                    points = 5  # Exact match
                elif (match_results[match]["home"] > match_results[match]["away"] and score["home"] > score["away"]) or \
                    (match_results[match]["home"] < match_results[match]["away"] and score["home"] < score["away"]) or \
                    (match_results[match]["home"] == match_results[match]["away"] and score["home"] == score["away"])  :
                    points = 3  # Correct outcome
                else:
                    points = 0  # No points

                user_points += points

        final_user_score = Score(
            week_id = week,
            user_id = prediction.user_id,
            points = user_points
        )
        db.session.add(final_user_score)
        db.session.commit()
        user_points = 0       
    flash(f"Scores for Week {week} computed and saved successfully!", "success")
    return redirect(url_for('home'))

    #return render_template('scores.html', form=form)



@app.route('/leaderboard', methods=['GET', 'POST'])
#@login_required
def leaderboard():
    scores = {}
    user_data = User.query.all()
    #points = Score.query.order_by(Score.user_id).all()
    for user in user_data:
        score = 0
        user_score = Score.query.filter_by(user_id=user.id).all()
        for sc in user_score:
            score += sc.points
            scores[f"{user.name}"] = score
        print(f"{user.name}: {score}")
        score = 0
    print(scores)
    sorted_scores = dict(sorted(scores.items(), key=lambda item: item[1], reverse=True))
    return render_template('leaderboard.html', scores=sorted_scores)



@app.route('/admin-dashboard', methods=['get', 'post'])
def admin():
    users = User.query.all()

    # New code to get table names
    inspector = inspect(db.engine)  # Create an inspector object
    table_names = inspector.get_table_names()  # Get the list of table names
    return render_template('admin.html', title='Admin Panel', users=users, tables=table_names)



@app.route('/toggle_role/<int:user_id>', methods=['POST'])
def toggle_role(user_id):
    # Fetch the user by ID
    user = User.query.get_or_404(user_id)
    # Get the current admin status from the form submission
    is_admin = request.form.get('is_admin')  # 'on' if checked, None if unchecked
    # Toggle the is_admin value based on the checkbox
    if is_admin:  # If the checkbox is checked, set is_admin to True
        user.is_admin = True
    else:  # If the checkbox is unchecked, set is_admin to False
        user.is_admin = False
    # Commit the changes to the database
    db.session.commit()
    # Redirect back to the user management page (or wherever you want)
    return redirect(url_for('admin'))



@app.route('/databases', methods=['get', 'post'])
def database():
    users = User.query.all()
    
    # New code to get table names
    inspector = inspect(db.engine)  # Create an inspector object
    table_names = inspector.get_table_names()  # Get the list of table names
    for t in table_names:
        print(t)
    return render_template('admin_panel.html', title='Admin Panel', users=users, tables=table_names)  # Pass table names to the template



@app.route('/clear-table', methods=['get', 'post'])
def clear_table():
    # Get the table name from the query parameters
    table_name = request.args.get('table_name')  # Get the table name from the href link
    if table_name and table_name in db.Model.metadata.tables:
        # Delete all records from the specified table
        db.session.query(db.Model.metadata.tables[table_name]).delete()
        db.session.commit()  # Commit the changes to the database
        flash(f"All records from the table '{table_name}' have been deleted.", 'success')
    else:
        flash(f"Table '{table_name}' does not exist.", 'danger')
    return redirect(url_for('admin'))  # Redirect back to the admin page



@app.route('/drop-table', methods=['get', 'post'])
def drop_table():
    table_name = request.args.get('table_name')  # Get the table name from the query parameters
    
    if table_name:
        try:
            # Use raw SQL to drop the table
            db.session.execute(text(f"DROP TABLE IF EXISTS {table_name}"))  # Removed CASCADE
            db.session.commit()  # Commit the changes to the database
            flash(f'Table {table_name} dropped successfully.', 'success')
        except Exception as e:
            flash(f'Error dropping table {table_name}: {str(e)}', 'danger')
    return redirect(url_for('admin'))  # Redirect to the admin panel or appropriate page



@app.route('/drop-table', methods=['get', 'post'])
def clear_weeks():
    # Delete all records from the Week table
    db.session.query(Week).delete()
    db.session.commit()  # Commit the changes to the database
    flash("All records from the Week table have been deleted.", 'success')
    return redirect(url_for('home'))  # Redirect back to the admin page



