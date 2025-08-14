from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, SelectField, DateTimeField, FieldList, FormField, SubmitField, DateTimeLocalField
from wtforms.validators import DataRequired, NumberRange
from datetime import datetime


EPL_TEAMS = [
    {'ARS':'Arsenal'}, {'AVL':' Aston Villa'}, {'BUR': 'Burnley'}, {'CHE': 'Chelsea'},
    {'BOU':'AFC Bournemouth'}, {'BRE':'Brentford'}, {'EVE':'Everton'}, {'FUL':'Fulham'}, {'LIV':'Liverpool'},
    {'MCI':'Manchester City'}, {'MUN':'Manchester United'}, {'NEW':'Newcastle United'}, {'TOT':'Tottenham Hotspur'},
    {'WOL':'Wolverhampton Wanderers'}, {'CRY':'Crystal Palace'}, {'SUN':'Sunderland'},
    {'WHU':'West Ham United'}, {'BHA':'Brighton & Hove Albion'}, {'LEE':'Leeds United'}, {'NFO':'Nottingham Forest'}
]

this_year = datetime.now().year


class FixtureForm(FlaskForm):

    home_team = SelectField('Home Team', validators=[DataRequired()])
    away_team = SelectField('Away Team', validators=[DataRequired()])
    submit = SubmitField('Submit')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        from .models import Team  # Import here to avoid circular import
        teams = Team.query.order_by(Team.name).all()
        choices = [(team.id, f"{team.name}") for team in teams]
        self.home_team.choices = choices
        self.away_team.choices = choices


# class FixtureForm(FlaskForm):
#     class Meta:
#         # Disable CSRF for this form since it's used within a FieldList
#         csrf = False
    
#     home_team_id = SelectField('Home Team', coerce=int, validators=[DataRequired()])
#     away_team_id = SelectField('Away Team', coerce=int, validators=[DataRequired()])
#     #match_datetime = DateTimeField('Match Date & Time', validators=[DataRequired()], format='%Y-%m-%dT%H:%M')


class NameForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    nickname = StringField('Nickname', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    google_id = StringField('Google ID', validators=[DataRequired()])

    submit = SubmitField('Submit')
    
    


class CreateMatchWeekForm(FlaskForm):
    # Don't import models at module level - do it in the route instead
    week_number = SelectField('Week Number', validators=[DataRequired()])
    season = SelectField('Season', validators=[DataRequired()])
    predictions_open_time = DateTimeField('Predictions Open Time', validators=[DataRequired()], format='%Y-%m-%dT%H:%M')
    predictions_close_time = DateTimeField('Predictions Close Time', validators=[DataRequired()], format='%Y-%m-%dT%H:%M')
    fixtures = FieldList(FormField(FixtureForm), min_entries=1, max_entries=20)
    submit = SubmitField('Create Match Week')


class PredictionForm(FlaskForm):
    #fixture_id = IntegerField('Fixture ID', validators=[DataRequired()])
    home_team_id = IntegerField('Home Score', validators=[DataRequired(), NumberRange(min=0, max=100)])
    home_score = IntegerField('Home Score', validators=[DataRequired()])
    away_team_id = IntegerField('Away Team', validators=[DataRequired()])
    away_score = IntegerField('Away Score', validators=[DataRequired(), NumberRange(min=0, max=20)])
    submit = SubmitField('Submit Prediction')
    


class CreateTeamForm(FlaskForm):
    name = StringField('Team Name', validators=[DataRequired()])
    short_name = StringField('Short Name', validators=[DataRequired()])
    nickname = StringField('Nickname', validators=[DataRequired()])
    submit = SubmitField('Submit')



class CreateSeasonForm(FlaskForm):
    start_year = IntegerField('Start Year', validators=[DataRequired()])
    end_year = IntegerField('End Year', validators=[DataRequired()])
    submit = SubmitField('Submit')



# ===============================================================
# ===============================================================

class MatchWeekForm(FlaskForm):
    # Don't import models at module level - do it in the route instead
    week_number = SelectField('Week Number', validators=[DataRequired()])
    season = SelectField('Season', validators=[DataRequired()])
    predictions_open_time = DateTimeLocalField('Predictions Open Time', validators=[DataRequired()], format='%Y-%m-%dT%H:%M')
    predictions_close_time = DateTimeLocalField('Predictions Close Time', validators=[DataRequired()], format='%Y-%m-%dT%H:%M')
    #submit = SubmitField('Create Match Week')


class MatchWeekUpdateForm(FlaskForm):
    # Don't import models at module level - do it in the route instead
    week_number = SelectField('Week Number', validators=[DataRequired()])
    season = SelectField('Season', validators=[DataRequired()])
    predictions_open_time = DateTimeLocalField('Predictions Open Time', validators=[DataRequired()], format='%Y-%m-%dT%H:%M')
    predictions_close_time = DateTimeLocalField('Predictions Close Time', validators=[DataRequired()], format='%Y-%m-%dT%H:%M')
    submit = SubmitField('Create Match Week')


class MatchRowForm(FlaskForm):
    """
    A form for a single match, containing fields for home team, scores, and away team.
    Note: We disable CSRF for this subform since it will be part of a larger form.
    """
    class Meta:
        csrf = False
    
    home_team = StringField('Home Team', validators=[DataRequired()])
    home_score = IntegerField('Home Score', validators=[NumberRange(min=0, message="Score must be 0 or greater")])
    away_team = StringField('Away Team', validators=[DataRequired()])
    away_score = IntegerField('Away Score', validators=[NumberRange(min=0, message="Score must be 0 or greater")])


# This is the main dynamic form. It uses a FieldList to hold multiple instances of MatchRowForm.
class DynamicMatchesForm(FlaskForm):
    """
    A dynamic form that contains a list of MatchRowForm instances.
    The number of matches in the list is determined by the initial user input.
    """
    matches = FieldList(FormField(MatchRowForm), min_entries=1)
    submit = SubmitField('Submit Scores')


class ViewGameWeekPredictionForm(FlaskForm):
    season = SelectField('Season', validators=[DataRequired()], coerce=int)
    match_week = SelectField('Match Week', validators=[DataRequired()], coerce=int)
    submit = SubmitField('View Predictions')

        
class SelectMatchWeekForm(FlaskForm):
    season = SelectField('Season', validators=[DataRequired()], coerce=int)
    match_week = SelectField('Match Week', validators=[DataRequired()], coerce=int)
    submit = SubmitField('View Predictions')




