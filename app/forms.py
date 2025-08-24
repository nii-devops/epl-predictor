from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, SelectField, DateTimeField, FieldList, EmailField, FormField, SubmitField, DateTimeLocalField, PasswordField, TelField
from wtforms.validators import DataRequired, Email, NumberRange, EqualTo, ValidationError
from datetime import datetime
import phonenumbers
import pycountry


from pycountrycode.countrycode import get_code, get_country, get_list_of_countries
countries_codes = get_list_of_countries()
country_code_data = []
for country in countries_codes:
    code = get_code(country)
    country_name = get_country(code)
    country_code_data.append((country_name, code))
    #print(f"Country: {country_name}, Code: {code}")



# Get all country codes and full country names
def get_country_codes():
    country_codes = []
    for code, region_codes in phonenumbers.COUNTRY_CODE_TO_REGION_CODE.items():
        if len(region_codes) > 0:
            # Use the first region code to find the country name
            region_code = region_codes[0]
            try:
                country_name = pycountry.countries.get(alpha_2=region_code).name
                country_codes.append((f'+{code}', f'{country_name} (+{code})'))
            except AttributeError:
                # Handle cases where pycountry doesn't have the country
                continue
    # Sort the list by country name for better user experience
    country_codes.sort(key=lambda x: x[1])
    return country_codes


# Custom validator to check if the phone number is valid for the selected country code
def validate_phone_number(form, field):
    try:
        # Construct the full number
        full_number = form.country_code.data + field.data
        # Parse and validate the number
        parsed_number = phonenumbers.parse(full_number, None)
        if not phonenumbers.is_valid_number(parsed_number):
            raise ValidationError('Invalid phone number for the selected country.')
    except phonenumbers.phonenumberutil.NumberParseException:
        raise ValidationError('Invalid phone number format.')



EPL_TEAMS = [
    {'ARS':'Arsenal'}, {'AVL':' Aston Villa'}, {'BUR': 'Burnley'}, {'CHE': 'Chelsea'},
    {'BOU':'AFC Bournemouth'}, {'BRE':'Brentford'}, {'EVE':'Everton'}, {'FUL':'Fulham'}, {'LIV':'Liverpool'},
    {'MCI':'Manchester City'}, {'MUN':'Manchester United'}, {'NEW':'Newcastle United'}, {'TOT':'Tottenham Hotspur'},
    {'WOL':'Wolverhampton Wanderers'}, {'CRY':'Crystal Palace'}, {'SUN':'Sunderland'},
    {'WHU':'West Ham United'}, {'BHA':'Brighton & Hove Albion'}, {'LEE':'Leeds United'}, {'NFO':'Nottingham Forest'}
]

this_year = datetime.now().year


class UserForm(FlaskForm):
    name = SelectField('Season', validators=[DataRequired()], coerce=int)
    season = SelectField('Season', validators=[DataRequired()], coerce=int)
    match_week = SelectField('Match Week', validators=[DataRequired()], coerce=int)
    submit = SubmitField('Submit')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        from .models import User, Season, Week  # Import here to avoid circular import
        users = User.query.order_by(User.name).all()
        seasons = Season.query.order_by(Season.season_start_year.desc()).all()
        weeks = Week.query.order_by(Week.week_number).all()

        # Populate the choices for the SelectFields
        self.name.choices = [(user.id, f"{user.name} | {user.nickname}") for user in users]
        self.season.choices = [(season.id, f"{season.season_start_year}-{season.season_end_year}") for season in seasons]
        self.match_week.choices = [(week.id, f"Week {week.week_number}") for week in weeks]



class EditUserForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    nickname = StringField('Nickname', validators=[DataRequired()])
    phone_no = StringField('Phone Number', validators=[DataRequired()])
    submit = SubmitField('Submit')



class TelephoneNumberForm(FlaskForm):
    country_code = SelectField('Country Code', choices=get_country_codes(), validators=[DataRequired()])
    phone_number = StringField('Telephone Number', validators=[DataRequired(), validate_phone_number])
    submit = SubmitField('Submit')



class ResetEmailForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Submit')



# New form class for the JavaScript-powered search
class SearchableUserForm(FlaskForm):
    # This form will be rendered with no pre-populated choices
    name = SelectField('User', validators=[DataRequired()], coerce=int, choices=[])
    submit = SubmitField('Submit')



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



class NameForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    nickname = StringField('Nickname', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    google_id = StringField('Google ID', validators=[DataRequired()])

    submit = SubmitField('Submit')
    


class RegisterForm(FlaskForm):
    name = StringField('Full Name', validators=[DataRequired()])
    nickname = StringField('Nickname', validators=[DataRequired()], render_kw={"placeholder": 'E.g. Sparkles'})
    email = EmailField('Email', validators=[DataRequired()], render_kw={"placeholder": 'E.g. kofimensah@gmail.com'})
    phone_no = StringField('Phone Number', validators=[DataRequired()], render_kw={"placeholder": 'E.g. 0244100200'})
    password_1 = PasswordField('Password', validators=[DataRequired()])
    password_2 = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password_1')])
    #google_id = StringField('Google ID', validators=[DataRequired()])

    submit = SubmitField('Submit')
    

class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Submit')


class PasswordResetForm(FlaskForm):
    password_1 = PasswordField('Password', validators=[DataRequired()])
    password_2 = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password_1')])
    submit = SubmitField('Submit')


class CreateMatchWeekForm(FlaskForm):
    # Don't import models at module level - do it in the route instead
    week_number = SelectField('Week Number', validators=[DataRequired()])
    season = SelectField('Season', validators=[DataRequired()])
    predictions_open_time = DateTimeField('Predictions Open Time', validators=[DataRequired()], format='%Y-%m-%dT%H:%M')
    predictions_close_time = DateTimeField('Predictions Close Time', validators=[DataRequired()], format='%Y-%m-%dT%H:%M')
    #close_time = DateTimeField('GameWeek Close Time', validators=[DataRequired()], format='%Y-%m-%dT%H:%M')
    fixtures = FieldList(FormField(FixtureForm), min_entries=1, max_entries=20)
    submit = SubmitField('Submit')


class PredictionForm(FlaskForm):
    #fixture_id = IntegerField('Fixture ID', validators=[DataRequired()])
    home_team_id = IntegerField('Home Score', validators=[DataRequired(), NumberRange(min=0, max=100)])
    home_score = IntegerField('Home Score', validators=[DataRequired()])
    away_team_id = IntegerField('Away Team', validators=[DataRequired()])
    away_score = IntegerField('Away Score', validators=[DataRequired(), NumberRange(min=0, max=20)])
    submit = SubmitField('Submit')
    


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
    submit = SubmitField('Submit')


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
    submit = SubmitField('Submit')


class ViewGameWeekPredictionForm(FlaskForm):
    season = SelectField('Season', validators=[DataRequired()], coerce=int)
    match_week = SelectField('Match Week', validators=[DataRequired()], coerce=int)
    submit = SubmitField('Submit')

        
class SelectMatchWeekForm(FlaskForm):
    season = SelectField('Season', validators=[DataRequired()], coerce=int)
    match_week = SelectField('Match Week', validators=[DataRequired()], coerce=int)
    submit = SubmitField('Submit')


class ProxyPredictionsForm(FlaskForm):
    name = SelectField('Name', validators=[DataRequired()], coerce=int)

    submit = SubmitField('Export Predictions')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        from .models import User  # Import here to avoid circular import
        users = User.query.order_by(User.id.desc()).all()
        self.name.choices = [(user.id, f"{user.name} | {user.nickname}") for user in users]



class SingleFixtureForm(FlaskForm):
    home_team = SelectField('Home Team', validators=[DataRequired()], coerce=int)
    home_score = IntegerField('Home Score', render_kw={"disabled": True})
    
    away_score = IntegerField('Away Score', render_kw={"disabled": True})
    away_team = SelectField('Away Team', validators=[DataRequired()], coerce=int)

    submit = SubmitField('Submit')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        from .models import Team  # Import here to avoid circular import
        teams = Team.query.order_by(Team.name).all()
        self.home_team.choices = [(team.id, f"{team.name}") for team in teams]
        self.away_team.choices = [(team.id, f"{team.name}") for team in teams]




class SingleFixtureScoreForm(FlaskForm):
    home_team = StringField('Home Team', render_kw={"disabled": True})
    home_score = IntegerField('Home Score', validators=[NumberRange(min=0, message="Score must be 0 or greater")])
    away_score = IntegerField('Away Score', validators=[NumberRange(min=0, message="Score must be 0 or greater")])
    away_team = StringField('Away Team', render_kw={"disabled": True})
    
    submit = SubmitField('Submit')

    


