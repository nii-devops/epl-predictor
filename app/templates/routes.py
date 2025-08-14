from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify, abort, send_file, make_response
from flask_login import login_user, login_required, logout_user, current_user
from datetime import date, datetime, timedelta
#from weasyprint import HTML
from sqlalchemy.engine import url
from .models import *
from .forms import *
from wtforms import FieldList, FormField
from . import oauth
import os
import io
from pprint import pprint
import pandas as pd
from fpdf import FPDF

bp = Blueprint('main', __name__)

ADMIN_EMAILS = os.getenv('ADMIN_EMAILS')

weeks = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 
        21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38]


"""
# Sky Sports API Integration (Mock implementation - replace with actual API)
def fetch_fixtures_from_sky_sports():
    # Get team IDs for the mock fixtures
    man_utd = Team.query.filter_by(name='Manchester United').first()
    arsenal = Team.query.filter_by(name='Arsenal').first()
    chelsea = Team.query.filter_by(name='Chelsea').first()
    liverpool = Team.query.filter_by(name='Liverpool').first()
    
    mock_fixtures = [
        {
            'home_team_id': man_utd.id if man_utd else None,
            'away_team_id': arsenal.id if arsenal else None,
            'match_datetime': datetime.now() + timedelta(days=7),
        },
        {
            'home_team_id': chelsea.id if chelsea else None,
            'away_team_id': liverpool.id if liverpool else None,
            'match_datetime': datetime.now() + timedelta(days=7, hours=2),
        }
    ]
    return mock_fixtures

"""




@bp.route('/')
def index():
    now = datetime.utcnow()
    active_match_weeks = MatchWeek.query.filter(MatchWeek.predictions_close_time > now).all()
    return render_template('index.html', active_match_weeks=active_match_weeks)


@bp.route('/login')
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    return render_template('login.html')


# The following routes require OAuth and app context, which will be handled in __init__.py
# Placeholders for now:
@bp.route('/authorize/google')
def google_auth():
    redirect_uri = url_for('main.google_callback', _external=True)
    #redirect_uri = os.getenv('REDIRECT_URI')  # Use environment variable if set
    return oauth.google.authorize_redirect(redirect_uri)


@bp.route('/authorize/google/callback')
def google_callback():
    token = oauth.google.authorize_access_token()
    user_info = token.get('userinfo')

    if not user_info:
        flash('Authentication failed', 'error')
        return redirect(url_for('main.login'))

    # Check if user exists by Google ID
    user = User.query.filter_by(google_id=user_info['sub']).first()

    # If not found by google_id, check by email
    if not user:
        user = User.query.filter_by(email=user_info['email']).first()

    if not user:
        # First-time Google login → redirect to set_nickname
        is_admin = 1 if user_info['email'] in ADMIN_EMAILS else 0
        return redirect(url_for(
            'main.set_nickname',
            google_id=user_info['sub'],
            email=user_info['email'],
            name=user_info['name'],
            is_admin=is_admin
        ))

    # If found, update details and log them in
    user.google_id = user_info['sub']
    user.name = user_info['name']
    db.session.commit()

    login_user(user)
    flash('Successfully logged in!', 'success')
    return redirect(url_for('main.index'))


@bp.route('/user/set-nickname', methods=['GET', 'POST'])
def set_nickname():
    google_id = request.args.get('google_id')
    email = request.args.get('email')
    name = request.args.get('name')
    is_admin = int(request.args.get('is_admin', 0))

    form = NameForm()

    # Pre-fill form on GET
    if request.method == 'GET':
        form.name.data = name
        form.email.data = email
        form.google_id.data = google_id

    if form.validate_on_submit():
        # Save user to DB
        user = User(
            nickname=form.nickname.data,
            email=form.email.data,
            name=form.name.data,
            google_id=google_id,
            is_admin=True if is_admin == 1 else False
        )
        db.session.add(user)
        db.session.commit()

        login_user(user)
        flash('Account created and logged in!', 'success')
        return redirect(url_for('main.index'))

    return render_template('admin/form.html', title='Set Nickname', heading='Set Nickname', form=form)




@bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('main.index'))


@bp.route('/admin')
@login_required
def admin_dashboard():
    now = datetime.utcnow()
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('main.index'))
    users = User.query.order_by(User.id).all()
    match_weeks = MatchWeek.query.order_by(MatchWeek.id).all()
    seasons = Season.query.order_by(Season.id).all()
    teams = Team.query.order_by(Team.id).all()
    return render_template('admin/dashboard.html', title='Admin Panel', now=now,
    users=users, match_weeks=match_weeks, seasons=seasons, teams=teams)


@bp.route('/create_weeks', methods=['GET', 'POST'])
@login_required
def create_weeks():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('main.index'))
    
    # Check if weeks already exist
    for week_num in range(1, 39):
        if Week.query.filter_by(week_number=week_num).first():
            flash(f'Week {week_num} already exists. Skipping creation.', 'warning')
            continue    
        
        week = Week(week_number=week_num)   
        db.session.add(week)
        
    db.session.commit()
    flash('Weeks created successfully!', 'success')
    return redirect(url_for('main.admin_dashboard'))



@bp.route('/admin/teams/populate', methods=['GET', 'POST'])
#@login_required
def populate_teams():
    # if not current_user.is_admin:
    #     flash('Access denied. Admin privileges required.', 'error')
    for team in EPL_TEAMS:
        for short_name, name in team.items():
            if not Team.query.filter_by(name=name).first():
                new_team = Team(name=name, short_name=short_name)
                db.session.add(new_team)
            else:
                print(f"Team {name} already exists, skipping.") 
                return redirect(request.referrer)
    db.session.commit()
    flash('Teams populated successfully!', 'success')
    return redirect(request.referrer)
    #return render_template('admin/matchweek.html', form=form, title='Create Match Week')


@bp.route('/admin/team/edit/<int:team_id>', methods=['GET', 'POST'])
@login_required
def edit_team(team_id):
    now = datetime.utcnow()
    team = Team.query.get_or_404(team_id)

    form = CreateTeamForm()
    if request.method == 'GET':
        pass
        form.name.data = team.name
        form.short_name.data = team.short_name
        form.nickname.data = team.nickname
    if form.validate_on_submit():
        team.name = form.name.data
        team.short_name = form.short_name.data
        if form.nickname.data:
            team.nickname = form.nickname.data
        team.updated_at = now
        db.session.commit()
        flash('Team Updated.', 'success')
        return redirect(url_for('main.admin_dashboard'))
    return render_template('admin/select_form.html', heading='Create/Edit Team', title='Create team', form=form)


@bp.route('/admin/test_route')
@login_required
def test_route():
    print("=== TEST ROUTE CALLED ===")
    return "Test route works!"


@bp.route('/admin/create_match_week', methods=['GET', 'POST'])
@login_required
def create_match_week():
    print("=== CREATE MATCH WEEK ROUTE CALLED ===")
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('main.index'))
    
    # Test database connection
    try:
        weeks = Week.query.order_by(Week.id).all()
        seasons = Season.query.order_by(Season.season_start_year.asc()).all()
        print(f"Found {len(seasons)} seasons in database")
    except Exception as e:
        flash(f'Database error: {str(e)}', 'error')
        return redirect(url_for('main.admin_dashboard'))
    
    week_choices = [(week.id, f"Week {week.week_number}") for week in weeks]
    season_choices = [(season.id, f"{season.season_start_year}-{season.season_end_year}") for season in seasons]
    
    # Get teams for fixture forms
    teams = Team.query.order_by(Team.name).all()
    team_choices = [(team.id, team.name) for team in teams]

    # Initialize form
    if request.method == 'POST':
        # Count the number of fixtures in the POST data
        num_fixtures = int(request.form.get('num_fixtures', 0))
        print(f"Number of fixtures detected in POST data: {num_fixtures}")
        
        # Create a new form class with the correct number of entries
        if num_fixtures > 0:
            # Create a dynamic form class with the right number of entries
            class DynamicCreateMatchWeekForm(CreateMatchWeekForm):
                fixtures = FieldList(FormField(FixtureForm), min_entries=num_fixtures, max_entries=20)
            
            form = DynamicCreateMatchWeekForm()
        else:
            form = CreateMatchWeekForm()
    else:
        form = CreateMatchWeekForm()
    
    # Set choices for the form fields
    form.season.choices = season_choices
    form.week_number.choices = week_choices
    
    # Set team choices for all fixture forms
    for fixture_form in form.fixtures:
        fixture_form.home_team_id.choices = team_choices
        fixture_form.away_team_id.choices = team_choices
        
    # Process form data if it's a POST request
    if request.method == 'POST':
        print(f"Processing form with {len(form.fixtures)} fixtures")
        form.process(request.form)
        print(f"After processing, form has {len(form.fixtures)} fixtures")
        
        # Re-set choices after processing (in case the form was recreated)
        for fixture_form in form.fixtures:
            fixture_form.home_team_id.choices = team_choices
            fixture_form.away_team_id.choices = team_choices

        # Check if form is submitted and valid
    if request.method == 'POST':
        print(f"Form data received: {request.form}")
        print(f"Number of fixtures in form: {len(form.fixtures)}")
        print(f"Form field names: {[field.name for field in form.fixtures]}")
        print(f"Form choices: week_number={form.week_number.choices}, season={form.season.choices}")
        
        if not form.validate():
            print(f"Form errors: {form.errors}")
            for field_name, errors in form.errors.items():
                print(f"Field {field_name} errors: {errors}")
            print(f"Form data: {form.data}")
        else:
            # Form is valid, process the submission
            for i, fixture_form in enumerate(form.fixtures):
                print(f'Processing fixture {i}: home_team_id={fixture_form.home_team_id.data}, away_team_id={fixture_form.away_team_id.data}')
                if fixture_form.home_team_id.data and fixture_form.away_team_id.data:
                    home_team = Team.query.get(fixture_form.home_team_id.data)
                    away_team = Team.query.get(fixture_form.away_team_id.data)
                    print(f'Fixture {i+1}: {home_team.name if home_team else "Unknown"} vs {away_team.name if away_team else "Unknown"}')
            
            try:
                match_week = MatchWeek(
                    week_id=form.week_number.data,
                    season_id=form.season.data,
                    predictions_open_time=form.predictions_open_time.data,
                    predictions_close_time=form.predictions_close_time.data
                )
                
                print(f'Creating MatchWeek: week_id={form.week_number.data}, season_id={form.season.data}')
                db.session.add(match_week)
                db.session.flush()  # This gets us the match_week.id
                print(f'MatchWeek created with ID: {match_week.id}')
                
                fixture_count = 0
                for fixture_form in form.fixtures:
                    if fixture_form.home_team_id.data and fixture_form.away_team_id.data:
                        fixture = Fixture(
                            match_week_id=match_week.id,
                            home_team_id=fixture_form.home_team_id.data,
                            away_team_id=fixture_form.away_team_id.data,
                        )
                        db.session.add(fixture)
                        fixture_count += 1
                        home_team = Team.query.get(fixture_form.home_team_id.data)
                        away_team = Team.query.get(fixture_form.away_team_id.data)
                        print(f'Added fixture: {home_team.name if home_team else "Unknown"} vs {away_team.name if away_team else "Unknown"}')
                
                db.session.commit()
                print(f'Successfully committed {fixture_count} fixtures to database')
                flash(f'Match Week created successfully with {fixture_count} fixtures!', 'success')
                return redirect(url_for('main.admin_dashboard'))
                
            except Exception as e:
                db.session.rollback()
                flash(f'Error creating match week: {str(e)}', 'error')
                return redirect(url_for('main.admin_dashboard'))
    else:
        print("=== FORM VALIDATION FAILED ===")
    return render_template('admin/create_match_week.html', form=form)


@bp.route('/admin/edit_match_week/<int:match_week_id>', methods=['GET', 'POST'])
def edit_match_week(match_week_id):
    if not current_user.is_admin:
        flash('Access denied!', 'danger')
        return redirect(request.referrer)
    match_week = MatchWeek.query.get_or_404(match_week_id)
    weeks = Week.query.order_by(Week.id).all()
    season = Season.query.filter_by(id=match_week.season_id).first()

    form = MatchWeekUpdateForm()
    form.season.choices = [(season.id, f"{season.season_start_year}/{season.season_end_year}")]
    form.week_number.choices = [(week.id, f"Week {week.week_number}") for week in weeks]
    # form.predictions_open_time.data = match_week.predictions_open_time
    # form.predictions_close_time.data = match_week.predictions_close_time

    if request.method == 'GET':
        form.predictions_open_time.data = match_week.predictions_open_time
        form.predictions_close_time.data = match_week.predictions_close_time
        form.season.data = match_week.season_id
        form.week_number.data = match_week.week_id

    if form.validate_on_submit():
        match_week.season_id = form.season.data
        match_week.week_id = form.week_number.data
        match_week.predictions_open_time = form.predictions_open_time.data
        match_week.predictions_close_time = form.predictions_close_time.data
        # write data to model
        
        db.session.commit()
        flash('Match week updated.', 'success')
        return redirect(url_for('main.admin_dashboard'))
    return render_template('admin/select_form.html', heading='Edit Match Week', title='Edit Match Week', form=form)



"""
@bp.route('/admin/import_fixtures', methods=['POST'])
@login_required
def import_fixtures():
    if not current_user.is_admin:
        return jsonify({'error': 'Access denied'}), 403
    try:
        fixtures = fetch_fixtures_from_sky_sports()
        flash(f'Imported {len(fixtures)} fixtures successfully!', 'success')
        return jsonify({'success': True, 'count': len(fixtures)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
"""


@bp.route('/admin/create_season', methods=['GET','POST'])
@login_required
def create_season():
    if not current_user.is_admin:
        return jsonify({'error': 'Access denied'}), 403
    form = CreateSeasonForm()

    if form.validate_on_submit():
        start = form.start_year.data
        end = form.end_year.data

        if Season.query.filter_by(season_start_year=start, season_end_year=end).first():
            flash('Season exists', 'warning')
            return redirect(request.referrer)
        else:
            try:
                db.session.add(
                    Season(
                        season_start_year=start,
                        season_end_year=end
                    )
                )
                db.session.commit()
                return redirect(url_for('main.index'))
            except Exception as e:
                #error = jsonify({'error': str(e)}), 500
                flash(f'Error: {e}', 'danger')
    return render_template('admin/form.html', form=form, heading='Create Season', title='Create Season')



@bp.route('/print-fixtures/<int:match_week_id>')
def print_fixtures(match_week_id):
    match_week = MatchWeek.query.get_or_404(match_week_id)
    for fx in match_week.fixtures:
        print(f'{fx.home_team.name} vs {fx.away_team.name}')
    return render_template('print_fixtures.html', week=match_week)



@bp.route('/admin/activate_match_week/<int:week_id>', methods=['POST'])
@login_required
def activate_match_week(week_id):
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('main.index'))
    MatchWeek.query.update({MatchWeek.is_active: False})
    match_week = MatchWeek.query.get_or_404(week_id)
    match_week.is_active = True
    db.session.commit()
    flash(f'Match Week {match_week.week_number} activated!', 'success')
    return redirect(url_for('main.admin_dashboard'))




@bp.route('/matches', methods=['GET', 'POST'])
@login_required
def predict():
    open_fixtures = Fixture.get_open_for_predictions()
    
    if not open_fixtures:
        flash("Predictions not open at the moment", 'info')
        return redirect(url_for('main.index'))

    # Get match_week_id from the first fixture
    match_week_id = open_fixtures[0].match_week_id
    match_week = MatchWeek.query.filter_by(id=match_week_id).first()
    fixture_id = Fixture.query.filter_by(match_week_id=match_week_id).first().id
    
    print(f"Found {len(open_fixtures)} open fixtures")
    print(f"Match Week ID: {match_week_id}")
    print(f"Match Week: {match_week}")

    # Get existing predictions for the current user and match week
    user_predictions = {}
    if current_user.is_authenticated:
        fixture_ids = [fixture.id for fixture in open_fixtures]
        existing_predictions = Prediction.query.filter(
            Prediction.user_id == current_user.id,
            Prediction.fixture_id.in_(fixture_ids)
        ).all()
        
        for prediction in existing_predictions:
            user_predictions[prediction.fixture_id] = prediction

    # Create form and populate with correct number of entries
    form = DynamicMatchesForm()
    
    # Populate the form with the correct number of match entries
    while len(form.matches) < len(open_fixtures):
        form.matches.append_entry()
    
    # Remove extra entries if needed
    while len(form.matches) > len(open_fixtures):
        form.matches.pop_entry()
    
    # Populate each form entry with fixture data
    for i, fixture in enumerate(open_fixtures):
        if i < len(form.matches):
            # Pre-populate the team names
            form.matches[i].home_team.data = fixture.home_team.name
            form.matches[i].away_team.data = fixture.away_team.name
            
            # If this is a GET request, pre-populate with existing predictions
            if request.method == 'GET':
                # Check if user has existing predictions for this fixture
                if current_user.is_authenticated and fixture.id in user_predictions:
                    prediction = user_predictions[fixture.id]
                    form.matches[i].home_score.data = prediction.home_score_prediction
                    form.matches[i].away_score.data = prediction.away_score_prediction
                else:
                    # Set default scores to 0 for display
                    form.matches[i].home_score.data = 0
                    form.matches[i].away_score.data = 0

    if request.method == 'POST':
        # Debug: Print form data to see what's being submitted
        print("Form data received:")
        print(request.form)
        
        if form.validate_on_submit():
            user_id = current_user.id
            print(f"User ID: {user_id}")
            
            # Process the submitted data and save to database
            predictions_saved = 0
            
            for i, match_form in enumerate(form.matches):
                # Get the corresponding fixture
                fixture = open_fixtures[i]
                fixture_id = fixture.id
                
                # Get team IDs
                home_team = Team.query.filter_by(name=match_form.home_team.data).first()
                away_team = Team.query.filter_by(name=match_form.away_team.data).first()
                
                if not home_team or not away_team:
                    flash(f'Error: Could not find team data for match {i+1}', 'error')
                    continue
                
                # Check if prediction already exists for this user and fixture
                existing_prediction = Prediction.query.filter_by(
                    user_id=user_id, 
                    fixture_id=fixture_id
                ).first()
                
                if existing_prediction:
                    # Update existing prediction
                    existing_prediction.home_team_id = home_team.id
                    existing_prediction.away_team_id = away_team.id
                    existing_prediction.home_score_prediction = match_form.home_score.data
                    existing_prediction.away_score_prediction = match_form.away_score.data
                    existing_prediction.updated_at = datetime.utcnow()
                    print(f"Updated prediction for fixture {fixture_id}: {home_team.name} {match_form.home_score.data} - {match_form.away_score.data} {away_team.name}")
                else:
                    # Create new prediction
                    prediction = Prediction(
                        user_id=user_id,
                        fixture_id=fixture_id,
                        home_team_id=home_team.id,
                        away_team_id=away_team.id,
                        home_score_prediction=match_form.home_score.data,
                        away_score_prediction=match_form.away_score.data
                    )
                    db.session.add(prediction)
                    print(f"Created prediction for fixture {fixture_id}: {home_team.name} {match_form.home_score.data} - {match_form.away_score.data} {away_team.name}")
                
                predictions_saved += 1
            
            # Commit all changes to database
            try:
                db.session.commit()
                flash(f'{predictions_saved} predictions saved successfully!', 'success')
            except Exception as e:
                db.session.rollback()
                flash(f'Error saving predictions: {str(e)}', 'error')
                print(f"Database error: {e}")

            return redirect(url_for('main.index'))
        else:
            flash('Please correct the errors in the form.', 'error')
    
    return render_template('predict.html', 
                         form=form, 
                         match_week=match_week,
                         user_predictions=user_predictions,
                         fixtures=open_fixtures)




@bp.route('/submit_prediction/<int:fixture_id>', methods=['POST'])
@login_required
def submit_prediction(fixture_id):
    fixture = Fixture.query.get_or_404(fixture_id)
    if not fixture.match_week.is_predictions_open:
        return jsonify({'error': 'Predictions are closed for this fixture'}), 400
    home_score = int(request.form['home_score'])
    away_score = int(request.form['away_score'])
    prediction = Prediction.query.filter_by(user_id=current_user.id, fixture_id=fixture_id).first()
    if prediction:
        prediction.home_score_prediction = home_score
        prediction.away_score_prediction = away_score
        prediction.updated_at = datetime.utcnow()
    else:
        prediction = Prediction(
            user_id=current_user.id,
            fixture_id=fixture_id,
            home_score_prediction=home_score,
            away_score_prediction=away_score
        )
        db.session.add(prediction)
    db.session.commit()
    return jsonify({'success': True})




@bp.route('/leaderboard')
@login_required
def leaderboard():
    from sqlalchemy import desc
    users = User.query.order_by(User.total_points.desc()).all()
    for user in users:
        user_scores = 0
        user_matchweekpoints = MatchWeekPoint.query.filter_by(user_id=user.id).all()
        for matchweekpoint in user_matchweekpoints:
            user_scores += matchweekpoint.points
        user.total_points = user_scores
    try:
        db.session.commit()
    except Exception as e:
        print(f"Error updating user scores: {e}")
        flash('Error updating leaderboard scores', 'error')
        return redirect(url_for('main.index'))

    return render_template('leaderboard.html', users=users, title='Leaderboard')



@bp.route('/api/add_fixture_form')
def add_fixture_form():
    form = FixtureForm()
    teams = Team.query.order_by(Team.name).all()
    team_choices = [(team.id, team.name) for team in teams]
    form.home_team_id.choices = team_choices
    form.away_team_id.choices = team_choices
    return render_template('admin/_fixture_form.html', form=form, index='__INDEX__', team_choices=team_choices)




@bp.route('/admin/fixture/create', methods=['GET', 'POST'])
def create_fixture():
    form = FixtureForm()
    matchform = MatchWeekForm()

    # Populate week and season choices
    week_options = [(week.id, f"Week {week.week_number}") for week in Week.query.order_by(Week.id).all()]
    season_options = [(season.id, f"{season.season_start_year}-{season.season_end_year}") for season in Season.query.order_by(Season.season_start_year.asc()).all()]
    matchform.week_number.choices = week_options
    matchform.season.choices = season_options

    if request.method == 'POST':
        # Fetch data from match week form
        week_id = request.form.get('week_number')
        season_id = request.form.get('season')
        predictions_open_time = datetime.strptime(request.form.get('predictions_open_time'), '%Y-%m-%dT%H:%M')
        predictions_close_time = datetime.strptime(request.form.get('predictions_close_time'), '%Y-%m-%dT%H:%M')

        print(f"Week ID: {week_id}, Season ID: {season_id}, Open Time: {predictions_open_time}, Close Time: {predictions_close_time}")

        # Validate the match week form
        if not week_id or not season_id or not predictions_open_time or not predictions_close_time:
            flash('All fields are required.', 'error')
            return redirect(request.referrer)
        
        if not MatchWeek.query.filter_by(week_id=week_id, season_id=season_id).first():
            try:
                match_week = MatchWeek(
                    week_id=week_id,
                    season_id=season_id,
                    predictions_open_time=predictions_open_time,
                    predictions_close_time=predictions_close_time
                )

                db.session.add(match_week)
                db.session.flush()

            except Exception as e:
                flash(f'Error: {e}', 'danger')
                return redirect(request.referrer)

        # Check if the week and season exist
        week = Week.query.get(week_id)
        season = Season.query.get(season_id)
        if not week or not season:
            flash('Invalid week or season selected.', 'error')
            return redirect(request.referrer)
        
        # Collect all fixture pairs from the POST data
        fixtures = []
        i = 0
        while True:
            home_key = f'home_team-{i}'
            away_key = f'away_team-{i}'
            if home_key in request.form and away_key in request.form:
                home_team = request.form[home_key]
                away_team = request.form[away_key]
                if not Fixture.query.filter_by(home_team_id=home_team, away_team_id=away_team, match_week_id=match_week.id).first():
                    print(f"Adding fixture: Home={home_team}, Away={away_team}")
                    db.session.add(
                        Fixture(
                        match_week_id=match_week.id,
                        home_team_id=home_team,
                        away_team_id=away_team
                    ))
                    db.session.commit()
                i += 1
            else:
                break
        # Print all fixtures
        for idx, (home, away) in enumerate(fixtures, 1):
            print(f"Row {idx}: Home Team = {home}, Away Team = {away}")
        flash(f'{len(fixtures)} fixtures submitted!', 'success')
        return redirect(request.referrer)
    return render_template('admin/create_fixtures.html', fixture_form=form, matchweek_form=matchform, title='Create Fixtures')


@bp.route('/admin/fixture/select-match-week', methods=['GET', 'POST'])
def select_fixture_matchweek():
    season = Season.query.order_by(Season.id.desc()).first()
    weeks = Week.query.order_by(Week.id).all()
    form = ViewGameWeekPredictionForm()

    form.season.choices = [(season.id, f"{season.season_start_year}/{season.season_end_year}" )]
    form.match_week.choices = [(week.id, f"Week {week.week_number}" ) for week in weeks]

    if form.validate_on_submit():
        week_id = form.match_week.data  # integer
        season_id = form.season.data 

        return redirect(url_for('main.update_fixture', week_id=week_id, season_id=season_id))

    return render_template('admin/form.html', form=form, heading='Select Match Week', title='Select Match Week')


@bp.route('/admin/fixture/update/<int:week_id>/<int:season_id>', methods=['GET', 'POST'])
def update_fixture(season_id, week_id):
    # Get the existing match week to update
    match_week = Week.query.get(week_id)
    season = Season.query.get(season_id)
    
    form = FixtureForm()
    matchform = MatchWeekForm()

    # Populate week and season choices
    week_options = [(week.id, f"Week {week.week_number}") for week in Week.query.order_by(Week.id).all()]
    season_options = [(season.id, f"{season.season_start_year}-{season.season_end_year}") for season in Season.query.order_by(Season.season_start_year.asc()).all()]
    matchform.week_number.choices = week_options
    matchform.season.choices = season_options

    # Pre-populate form with existing data for GET requests
    if request.method == 'GET':
        matchform.week_number.data = match_week.week_id
        matchform.season.data = match_week.season_id
        matchform.predictions_open_time.data = match_week.predictions_open_time
        matchform.predictions_close_time.data = match_week.predictions_close_time

    if request.method == 'POST':
        # Fetch data from match week form
        week_id = request.form.get('week_number')
        season_id = request.form.get('season')
        predictions_open_time = datetime.strptime(request.form.get('predictions_open_time'), '%Y-%m-%dT%H:%M')
        predictions_close_time = datetime.strptime(request.form.get('predictions_close_time'), '%Y-%m-%dT%H:%M')

        print(f"Updating Match Week {match_week.week_id}: Week ID: {week_id}, Season ID: {season_id}, Open Time: {predictions_open_time}, Close Time: {predictions_close_time}")

        # Validate the match week form
        if not week_id or not season_id or not predictions_open_time or not predictions_close_time:
            flash('All fields are required.', 'error')
            return redirect(request.referrer)

        # Check if the week and season exist
        week = Week.query.get(week_id)
        season = Season.query.get(season_id)
        if not week or not season:
            flash('Invalid week or season selected.', 'error')
            return redirect(request.referrer)

        try:
            # Update the existing match week
            match_week.week_id = week_id
            match_week.season_id = season_id
            match_week.predictions_open_time = predictions_open_time
            match_week.predictions_close_time = predictions_close_time

            # Delete existing fixtures for this match week
            existing_fixtures = Fixture.query.filter_by(match_week_id=match_week.id).all()
            for fixture in existing_fixtures:
                db.session.delete(fixture)

            # Collect all fixture pairs from the POST data and create new ones
            fixtures_added = 0
            i = 0
            while True:
                home_key = f'home_team-{i}'
                away_key = f'away_team-{i}'
                if home_key in request.form and away_key in request.form:
                    home_team = request.form[home_key]
                    away_team = request.form[away_key]
                    if home_team and away_team:  # Only add if both teams are selected
                        print(f"Updating fixture: Home={home_team}, Away={away_team}")
                        db.session.add(
                            Fixture(
                            match_week_id=match_week.id,
                            home_team_id=home_team,
                            away_team_id=away_team
                        ))
                        fixtures_added += 1
                    i += 1
                else:
                    break

            db.session.commit()
            flash(f'Match week updated successfully! {fixtures_added} fixtures updated.', 'success')
            return redirect(url_for('main.admin_dashboard'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error updating match week: {e}', 'danger')
            return redirect(request.referrer)

    # Get existing fixtures for display
    existing_fixtures = Fixture.query.filter_by(match_week_id=match_week.id).all()
    
    return render_template('admin/create_fixtures.html', 
                         fixture_form=form, 
                         matchweek_form=matchform, 
                         title='Update Fixtures',
                         match_week=match_week,
                         existing_fixtures=existing_fixtures)




@bp.route('/admin/scores/select-match-week', methods=['GET', 'POST'])
def select_scores_matchweek():
    season = Season.query.order_by(Season.id.desc()).first()
    weeks = Week.query.order_by(Week.id).all()
    form = ViewGameWeekPredictionForm()

    form.season.choices = [(season.id, f"{season.season_start_year}/{season.season_end_year}" )]
    form.match_week.choices = [(week.id, f"Week {week.week_number}" ) for week in weeks]

    if form.validate_on_submit():
        week_id = form.match_week.data  # integer
        season_id = form.season.data 

        return redirect(url_for('main.update_scores', week_id=week_id, season_id=season_id))

    return render_template('admin/form.html', form=form, heading='Select Match Week', title='Select Match Week')



@bp.route('/admin/fixture/update-scores/<int:week_id>/<int:season_id>', methods=['GET', 'POST'])
def update_scores(week_id, season_id):
    if not current_user.is_admin:
        flash('Access denied!', 'danger')
        return redirect(url_for('main.index'))

    now = datetime.utcnow()
    week = Week.query.get_or_404(week_id)
    season = Season.query.get_or_404(season_id)
    match_week = MatchWeek.query.filter_by(season_id=season.id, week_id=week.id).first_or_404()

    if now < match_week.predictions_close_time:
        flash('Predictions must be closed before updating scores.', 'info')
        return redirect(url_for('main.index'))

    # Retrieve fixtures from the Fixture model
    fixtures = Fixture.query.filter_by(match_week_id=match_week.id).all()
    if not fixtures:
        flash("No fixtures found for this match week.", 'info')
        return redirect(url_for('main.index'))

    # Create dynamic form
    form = DynamicMatchesForm()

    # Adjust form fields to match number of fixtures
    while len(form.matches) < len(fixtures):
        form.matches.append_entry()
    while len(form.matches) > len(fixtures):
        form.matches.pop_entry()

    if request.method == 'GET':
        # Populate form with fixture data
        for i, fixture in enumerate(fixtures):
            form.matches[i].home_team.data = fixture.home_team.name
            form.matches[i].away_team.data = fixture.away_team.name
            form.matches[i].home_score.data = fixture.home_score or 0
            form.matches[i].away_score.data = fixture.away_score or 0

    elif form.validate_on_submit():
        # Update scores in the Fixture model
        updated = 0
        for i, match_form in enumerate(form.matches):
            fixture = fixtures[i]
            fixture.home_score = match_form.home_score.data
            fixture.away_score = match_form.away_score.data
            
            # Mark fixture as completed if both scores are provided
            if fixture.home_score is not None and fixture.away_score is not None:
                fixture.is_completed = True
            
            updated += 1

        try:
            db.session.commit()
            flash(f'Successfully updated {updated} fixtures.', 'success')
            # Optionally, you can recalculate points for users based on the updated scores
            for fixture in fixtures:
                if fixture.is_completed:
                    # Calculate points for each user based on the fixture scores
                    predictions = Prediction.query.filter_by(fixture_id=fixture.id).all()
                    for prediction in predictions:
                        if prediction.home_score_prediction == fixture.home_score and prediction.away_score_prediction == fixture.away_score:
                            prediction.points_earned = 5  # Correct score
                        elif (prediction.home_score_prediction > prediction.away_score_prediction and fixture.home_score > fixture.away_score) or \
                             (prediction.home_score_prediction < prediction.away_score_prediction and fixture.home_score < fixture.away_score) or \
                             (prediction.home_score_prediction == prediction.away_score_prediction and fixture.home_score == fixture.away_score):
                            prediction.points_earned = 3
                        
                            prediction.points_earned = 0
            return redirect(url_for('main.admin_dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating scores: {e}', 'danger')
            return redirect(url_for('main.admin_dashboard'))

    return render_template(
        'update_scores.html',
        form=form,
        title='Update Scores',
        heading='Update Fixture Scores',
        match_week=match_week,
        fixtures=fixtures
    )



"""
@bp.route('/admin/view-prediction/select-match-week', methods=['GET', 'POST'])
def view_prediction_matchweek():
    season = Season.query.order_by(Season.id.desc()).first()
    weeks = Week.query.order_by(Week.id).all()
    form = SelectMatchWeekForm()

    form.season.choices = [(season.id, f"{season.season_start_year}/{season.season_end_year}")]
    form.match_week.choices = [(week.id, f"Week {week.week_number}" ) for week in weeks]

    if form.validate_on_submit():
        week_id = form.match_week.data  # integer
        season_id = form.season.data 

        match_week = MatchWeek.query.filter_by(season_id=season_id, week_id=week_id).first()
        if not match_week:
            flash('Match week not found for the selected season and week.', 'error')
            return redirect(request.referrer)

        return redirect(url_for('main.update_fixture', match_week_id=match_week.id))

    return render_template('admin/form.html', form=form, heading='Select Match Week', title='Select Match Week')
"""


@bp.route('/view-predictions', methods=['GET', 'POST'])
def view_prediction():
    user_id = current_user.id
    form = ViewGameWeekPredictionForm()
    predictions = []
    fixtures = []
    selected_season = None
    selected_match_week = None

    # Get all seasons for dropdown
    seasons = Season.query.order_by(Season.season_start_year.desc()).all()
    season_choices = [(s.id, f"{s.season_start_year}/{s.season_end_year}") for s in seasons]
    
    # Get the latest season to show match weeks for
    latest_season = Season.query.order_by(Season.season_start_year.desc()).first()
    
    if latest_season:
        # Get match weeks for the latest season
        match_weeks = MatchWeek.query.filter_by(season_id=latest_season.id).order_by(MatchWeek.week_id).all()
        week_options = [(mw.id, f"Week {mw.week.week_number}") for mw in match_weeks]
    else:
        week_options = []


    form.season.choices = season_choices
    form.match_week.choices = week_options
    
    if form.validate_on_submit():
        selected_season_id = form.season.data
        selected_match_week_id = form.match_week.data
        
        # Get the selected season and match week
        selected_season = Season.query.get(selected_season_id)
        selected_match_week = MatchWeek.query.get(selected_match_week_id)
        
        if selected_match_week:
            # Get fixtures for the selected match week
            fixtures = Fixture.query.filter_by(match_week_id=selected_match_week_id).all()
            
            # Get all predictions for these fixtures
            fixture_ids = [fixture.id for fixture in fixtures]
            predictions = Prediction.query.filter(Prediction.fixture_id.in_(fixture_ids)).filter_by(user_id=user_id).all()
            
            print(f"Found {len(fixtures)} fixtures and {len(predictions)} predictions for match week {selected_match_week_id}")
    
    return render_template('view_predictions.html', 
                         form=form, 
                         predictions=predictions, 
                         fixtures=fixtures,
                         selected_season=selected_season,
                         selected_match_week=selected_match_week)
    


@bp.route('/select-scoring-matchweek', methods=['GET', 'POST'])
def select_scoring_matchweek():
    form = MatchWeekForm()
    return render_template('admin/form.html', heading='Select Match Week', title='Select Match Week', form=form)



@bp.route('/generate-matchweek-points/<int:match_week_id>', methods=['GET', 'POST'])
@login_required
def generate_matchweek_points(match_week_id):
    if current_user.is_anonymous or not current_user.is_admin:
        flash('Access denied!', 'danger')
        return redirect(url_for('main.index'))
    
    match_week = MatchWeek.query.get_or_404(match_week_id)

    fixtures = Fixture.query.filter_by(match_week_id=match_week_id).all()
    
    if not fixtures:
        flash('No fixtures found', 'info')
        return redirect(url_for('main.admin_dashboard'))
    for fx in fixtures:
        print(f"home {fx.home_team.name}: {fx.home_score}")

    # Generate a list of users...
    users = User.query.order_by(User.id).all()
    for user in users:
        user_id = user.id
        print(f"{user.email}")
        user_score = 0
        user_predictions = Prediction.query.filter_by(user_id=user_id).order_by(Prediction.id).all()
        for prediction in user_predictions:
            fixture = Fixture.query.filter_by(home_team_id=prediction.home_team_id, away_team_id=prediction.away_team_id).first()
            if fixture.home_score == prediction.home_score_prediction and fixture.away_score == prediction.away_score_prediction:
                user_score += 5
            elif (fixture.home_score == fixture.away_score and prediction.home_score_prediction == prediction.away_score_prediction) or (fixture.home_score < fixture.away_score and 
                prediction.home_score_prediction < prediction.away_score_prediction) or (fixture.home_score > fixture.away_score and prediction.home_score_prediction > prediction.away_score_prediction):
                user_score += 3
            else:
                user_score += 0
        #print(f"{user.name} : {user_score}")

        # Here you would save the user_score to the MatchWeekPoint model
        if MatchWeekPoint.query.filter_by(user_id=user_id, match_week_id=match_week_id).first():
            flash("Game Week Points already exist!", 'danger')
            return redirect(request.referrer)
        # Create a new MatchWeekPoint entry        
        match_week_point = MatchWeekPoint(user_id=user_id, match_week_id=match_week_id, season_id=match_week.season_id, points=user_score)
        db.session.add(match_week_point)
    try:
        db.session.commit()
        flash('Match week points generated successfully!', 'success')
        return redirect(url_for('main.weekly_leaderboard', match_week_id=match_week_id))
    except Exception as e:
        db.session.rollback()
        flash(f'Error generating match week points: {str(e)}', 'danger')
        return redirect(url_for('main.admin_dashboard'))



@bp.route('/select-weekly-leaderboard-matchweek', methods=['GET', 'POST'])
def select_weekly_leaderboard_matchweek():
    form = SelectMatchWeekForm()

    # ✅ Always set choices before validation
    seasons = Season.query.order_by(Season.season_start_year.desc()).all()
    form.season.choices = [(season.id, f"{season.season_start_year}/{season.season_end_year}") for season in seasons]

    weeks = Week.query.order_by(Week.id).all()
    form.match_week.choices = [(week.id, f"Week {week.week_number}") for week in weeks]

    if form.validate_on_submit():
        season_id = form.season.data
        match_week_id = form.match_week.data
        match_week = MatchWeek.query.filter_by(season_id=season_id, week_id=match_week_id).first()
        if not match_week:
            flash('Match week not found for the selected season and week.', 'warning')
            return redirect(request.referrer)

        return redirect(url_for('main.weekly_leaderboard', match_week_id=match_week.id))

    return render_template('admin/form.html', heading='Select Match Week', title='Select Match Week', form=form)



@bp.route('/leaderboard/weekly/<int:match_week_id>', methods=['GET', 'POST'])
def weekly_leaderboard(match_week_id):
    match_week = MatchWeek.query.get_or_404(match_week_id)
    weekly_scores = MatchWeekPoint.query.filter_by(match_week_id=match_week_id).order_by(MatchWeekPoint.points.desc()).all()
    users = User.query.order_by(User.name).all()
    if not weekly_scores:
        flash('No weekly scores found', 'info')
        return redirect(url_for('main.index'))
    return render_template('weekly_leaderboard.html', weekly_scores=weekly_scores, title='Weekly Leaderboard', match_week_id=match_week_id,
                           users=users, heading='Weekly Leaderboard', subheading=f'Weekly Leaderboard for Match Week {match_week.week.week_number}')



@bp.route('/download_scores_excel')
@login_required
def download_scores_excel():
    if current_user.is_anonymous or not current_user.is_admin:
        flash('Access denied!', 'danger')
        return redirect(url_for('main.index'))
    """
    Generates an Excel file of the weekly_scores table:
    Rank | Name | Nickname | Points
    """

    # If your page is scoped by a week, pass ?week_id=... from the button.
    week_id = request.args.get('week_id', type=int)

    # --- Get the same data you use for the HTML table ---
    # Adjust these queries to match your app logic.
    query = MatchWeekPoint.query
    if week_id:
        query = query.filter_by(week_id=week_id)

    # Ensure ordering by points desc so Rank matches the page
    weekly_scores = query.order_by(MatchWeekPoint.points.desc()).all()

    user_ids = [s.user_id for s in weekly_scores]
    users = User.query.filter(User.id.in_(user_ids)).all()
    user_map = {u.id: u for u in users}

    # Build rows
    rows = []
    for idx, score in enumerate(weekly_scores, start=1):
        u = user_map.get(score.user_id)
        rows.append({
            "Rank": idx,
            "Name": getattr(u, "name", "") if u else "",
            "Nickname": getattr(u, "nickname", "") if u else "",
            "Points": score.points
        })

    # Create Excel in-memory
    output = io.BytesIO()
    df = pd.DataFrame(rows, columns=["Rank", "Name", "Nickname", "Points"])
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="Weekly Scores")

        # Optional: autosize columns
        ws = writer.sheets["Weekly Scores"]
        for col_cells in ws.columns:
            max_len = max(len(str(c.value)) if c.value is not None else 0 for c in col_cells)
            ws.column_dimensions[col_cells[0].column_letter].width = max_len + 2

    output.seek(0)
    filename = f"weekly_scores{'_'+str(week_id) if week_id else ''}.xlsx"

    return send_file(
        output,
        as_attachment=True,
        download_name=filename,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )



@bp.route('/download/weekly_leaderboard_pdf/<int:match_week_id>')
@login_required
def download_weekly_leaderboard_pdf(match_week_id):
    if current_user.is_anonymous or not current_user.is_admin:
        flash('Access denied!', 'danger')
        return redirect(url_for('main.index'))
    """
    Generates and downloads a PDF of the weekly leaderboard using FPDF2.
    
    This function retrieves the necessary data from the database, builds a PDF
    with a header and a table, and returns it as a downloadable file.
    """
    
    match_week = MatchWeek.query.get_or_404(match_week_id)
    if not match_week:
        # Returning a simple text response in this case.
        # In a real app, you might render an error template.
        return "Match week not found.", 404

    weekly_scores = MatchWeekPoint.query.filter_by(match_week_id=match_week_id).order_by(MatchWeekPoint.points.desc()).all()
    users = User.query.order_by(User.name).all()
    
    # Check if there are scores to display.
    if not weekly_scores:
        return "No scores found for this match week.", 404
        
    # Create a dictionary for efficient user lookup
    users_dict = {user.id: user for user in users}
    
    # Initialize FPDF object
    pdf = FPDF(orientation='P', unit='mm', format='A4')
    pdf.add_page()
    
    # Add a title and subtitle
    pdf.set_font('Arial', 'B', 16)
    pdf.cell(200, 10, 'Weekly Leaderboard', ln=1, align='C')
    pdf.set_font('Arial', '', 14)
    pdf.cell(200, 10, f'Match Week {match_week.week.week_number}', ln=1, align='C')
    pdf.ln(10)

    # Define table headers and widths
    headers = ['Rank', 'Name', 'Nickname', 'Points']
    col_widths = [20, 65, 65, 30]

    # Draw table headers
    pdf.set_font('Arial', 'B', 12)
    pdf.set_fill_color(45, 0, 46) 
    pdf.set_text_color(255, 255, 255)
    for i, header in enumerate(headers):
        pdf.cell(col_widths[i], 10, header, border=1, ln=0 if i < len(headers)-1 else 1, align='C', fill=True)

    # Draw table rows
    pdf.set_font('Arial', '', 12)
    pdf.set_text_color(0, 0, 0)
    fill = False
    for i, score in enumerate(weekly_scores):
        user_info = users_dict.get(score.user_id)
        if user_info:
            row_data = [
                str(i + 1),
                user_info.name,
                user_info.nickname,
                str(score.points)
            ]
            pdf.set_fill_color(240, 240, 240) if fill else pdf.set_fill_color(255, 255, 255)
            for j, data in enumerate(row_data):
                pdf.cell(col_widths[j], 10, data, border=1, ln=0 if j < len(row_data)-1 else 1, align='C', fill=True)
            fill = not fill

    # Output the PDF to a BytesIO object
    pdf_output = io.BytesIO()
    # Get the raw PDF bytes as a bytearray
    pdf_bytes = pdf.output(dest='S')
    # Write the bytes to the BytesIO stream
    pdf_output.write(pdf_bytes)
    # Seek to the beginning of the stream before returning
    pdf_output.seek(0)
    
    # Create a Flask response object
    response = make_response(pdf_output.getvalue())
    
    # Set the headers for the PDF download
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=weekly_leaderboard_match_week_{match_week_id}.pdf'
    
    return response


@bp.route('/download/leaderboard_pdf')
@login_required
def download_leaderboard_pdf():
    if current_user.is_anonymous or not current_user.is_admin:
        flash('Access denied!', 'danger')
        return redirect(url_for('main.index'))
    """
    Generates and downloads a PDF of the weekly leaderboard using FPDF2.
    
    This function retrieves the necessary data from the database, builds a PDF
    with a header and a table, and returns it as a downloadable file.
    """
    
    users = User.query.order_by(User.total_points.desc()).all()

    # Initialize FPDF object
    pdf = FPDF(orientation='P', unit='mm', format='A4')
    pdf.add_page()
    
    # Add a title and subtitle
    pdf.set_font('Arial', 'B', 16)
    pdf.cell(200, 10, 'Leaderboard', ln=1, align='C')
    pdf.set_font('Arial', '', 14)
    pdf.cell(200, 10, ln=1, align='C')
    #pdf.cell(200, 10, f'Match Week {match_week.week.week_number}', ln=1, align='C')
    pdf.ln(10)

    # Define table headers and widths
    headers = ['Rank', 'Name', 'Nickname', 'Points']
    col_widths = [20, 65, 65, 30]

    # Draw table headers
    pdf.set_font('Arial', 'B', 12)
    pdf.set_fill_color(45, 0, 46) 
    pdf.set_text_color(255, 255, 255)
    for i, header in enumerate(headers):
        pdf.cell(col_widths[i], 10, header, border=1, ln=0 if i < len(headers)-1 else 1, align='C', fill=True)

    # Draw table rows
    pdf.set_font('Arial', '', 12)
    pdf.set_text_color(0, 0, 0)
    fill = False
    for i, user in enumerate(users):
        #user_info = users_dict.get(user.user_id)
        if user:
            row_data = [
                str(i + 1),
                user.name,
                user.nickname,
                str(user.total_points)
            ]
            pdf.set_fill_color(240, 240, 240) if fill else pdf.set_fill_color(255, 255, 255)
            for j, data in enumerate(row_data):
                pdf.cell(col_widths[j], 10, data, border=1, ln=0 if j < len(row_data)-1 else 1, align='C', fill=True)
            fill = not fill

    # Output the PDF to a BytesIO object
    pdf_output = io.BytesIO()
    # Get the raw PDF bytes as a bytearray
    pdf_bytes = pdf.output(dest='S')
    # Write the bytes to the BytesIO stream
    pdf_output.write(pdf_bytes)
    # Seek to the beginning of the stream before returning
    pdf_output.seek(0)
    
    # Create a Flask response object
    response = make_response(pdf_output.getvalue())
    
    # Set the headers for the PDF download
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=leaderboard.pdf'
    
    return response






