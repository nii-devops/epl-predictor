
from flask_login import UserMixin
from datetime import datetime
from sqlalchemy import UniqueConstraint
from . import db

# Association tables (add constraint names for clarity)
season_week = db.Table(
    'season_week',
    db.Column('season_id', db.Integer, db.ForeignKey('season.id', ondelete='CASCADE', name='fk_season_week_season_id'), primary_key=True),
    db.Column('week_id', db.Integer, db.ForeignKey('week.id', ondelete='CASCADE', name='fk_season_week_week_id'), primary_key=True)
)

season_team = db.Table(
    'season_team',
    db.Column('season_id', db.Integer, db.ForeignKey('season.id', ondelete='CASCADE', name='fk_season_team_season_id'), primary_key=True),
    db.Column('team_id', db.Integer, db.ForeignKey('team.id', ondelete='CASCADE', name='fk_season_team_team_id'), primary_key=True)
)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    nickname = db.Column(db.String(100), nullable=False)
    phone_no = db.Column(db.String(15), nullable=True)
    password = db.Column(db.String(120), nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    predictions = db.relationship('Prediction', backref='user', lazy=True, cascade="all, delete-orphan")
    total_points = db.Column(db.Integer, nullable=False, default=0)

    __table_args__ = (
        UniqueConstraint('email', name='uq_user_email'),
    )

    def __repr__(self):
        return f'<User {self.email}>'


class Season(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    season_start_year = db.Column(db.Integer, nullable=False)
    season_end_year = db.Column(db.Integer, nullable=False)
    match_weeks = db.relationship('MatchWeek', backref='season', lazy=True, cascade="all, delete-orphan")


class Week(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    week_number = db.Column(db.Integer, nullable=False)


class MatchWeek(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    season_id = db.Column(db.Integer, db.ForeignKey('season.id', ondelete='CASCADE', name='fk_matchweek_season_id'), nullable=False)
    week_id = db.Column(db.Integer, db.ForeignKey('week.id', ondelete='CASCADE', name='fk_matchweek_week_id'), nullable=False)
    week = db.relationship('Week')
    predictions_open_time = db.Column(db.DateTime, nullable=False)
    predictions_close_time = db.Column(db.DateTime, nullable=False)
    close_time = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    fixtures = db.relationship('Fixture', backref='match_week', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f'<MatchWeek {self.week_id}: Season {self.season_id}>'


    # @property
    # def is_predictions_open(self):
    #     from datetime import datetime
        
    #     now = datetime.utcnow()
        
    #     # Handle None values
    #     if not self.predictions_open_time or not self.predictions_close_time:
    #         return False
        
    #     try:
    #         # Ensure we're comparing datetime objects
    #         open_time = self.predictions_open_time
    #         close_time = self.predictions_close_time
            
    #         # If they're not datetime objects, this will fail gracefully
    #         return open_time <= now <= close_time
    #     except TypeError:
    #         # If comparison fails due to type mismatch, return False
    #         return False


    @property
    def is_predictions_open(self):
        now = datetime.utcnow()
        return self.predictions_open_time <= now <= self.predictions_close_time
    

class Fixture(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    match_week_id = db.Column(db.Integer, db.ForeignKey('match_week.id', ondelete='CASCADE', name='fk_fixture_matchweek_id'), nullable=False)
    home_team_id = db.Column(db.Integer, db.ForeignKey('team.id', ondelete='CASCADE', name='fk_fixture_home_team_id'), nullable=False)
    away_team_id = db.Column(db.Integer, db.ForeignKey('team.id', ondelete='CASCADE', name='fk_fixture_away_team_id'), nullable=False)
    match_datetime = db.Column(db.DateTime, nullable=True)
    home_score = db.Column(db.Integer, nullable=True)
    away_score = db.Column(db.Integer, nullable=True)
    is_completed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    predictions = db.relationship('Prediction', backref='fixture', lazy=True, cascade="all, delete-orphan")

    home_team = db.relationship('Team', foreign_keys=[home_team_id], backref='home_fixtures')
    away_team = db.relationship('Team', foreign_keys=[away_team_id], backref='away_fixtures')

    # Add this to the Fixture class in models.py
    @classmethod
    def get_open_for_predictions(cls):
        """Get all fixtures where predictions are currently open"""
        now = datetime.utcnow()
        return cls.query.join(MatchWeek).filter(
            MatchWeek.predictions_open_time <= now,
            MatchWeek.predictions_close_time >= now
        ).all()

    def __repr__(self):
        return f'<Fixture {self.home_team.name if self.home_team else "Unknown"} vs {self.away_team.name if self.away_team else "Unknown"}>'


class Prediction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE', name='fk_prediction_user_id'), nullable=False)
    fixture_id = db.Column(db.Integer, db.ForeignKey('fixture.id', ondelete='CASCADE', name='fk_prediction_fixture_id'), nullable=False)
    home_team_id = db.Column(db.Integer, db.ForeignKey('team.id', ondelete='CASCADE', name='fk_prediction_home_team_id'), nullable=False)
    away_team_id = db.Column(db.Integer, db.ForeignKey('team.id', ondelete='CASCADE', name='fk_prediction_away_team_id'), nullable=False)
    home_score_prediction = db.Column(db.Integer, nullable=False)
    away_score_prediction = db.Column(db.Integer, nullable=False)
    points_earned = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    home_team = db.relationship('Team', foreign_keys=[home_team_id], backref='home_predictions')
    away_team = db.relationship('Team', foreign_keys=[away_team_id], backref='away_predictions')


class Team(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)
    short_name = db.Column(db.String(10), nullable=True)
    logo_url = db.Column(db.String(200), nullable=True)
    nickname = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint('name', name='uq_team_name'),
    )

    def __repr__(self):
        return f'<{self.name}>'


class MatchWeekPoint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE', name='fk_mwp_user_id'), nullable=False)
    match_week_id = db.Column(db.Integer, db.ForeignKey('match_week.id', ondelete='CASCADE', name='fk_mwp_matchweek_id'), nullable=False)
    rank = db.Column(db.Integer, nullable=True)
    points = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = db.relationship('User', backref='match_week_scores')
    match_week = db.relationship('MatchWeek', backref='scores')

    def rank_user(self):
        scores = MatchWeekPoint.query.filter_by(match_week_id=self.match_week_id)\
            .order_by(MatchWeekPoint.points.desc()).all()
        rank = 1
        for score in scores:
            if score.user_id == self.user_id:
                self.rank = rank
                break
            rank += 1

    def __repr__(self):
        return f'<MatchWeekPoint User {self.user_id} Week {self.match_week_id} Points {self.points}>'



