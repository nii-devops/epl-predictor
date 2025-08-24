#!/usr/bin/env python3
"""
Script to populate the Week table with EPL weeks 1-38
Run this after your migrations are complete
"""

from app import create_app
from app.models import db, Week


def create_weeks():
    app = create_app()
    
    with app.app_context():
        # Check if weeks already exist
        existing_weeks = Week.query.count()
        if existing_weeks > 0:
            print(f"Weeks already exist ({existing_weeks} found). Skipping creation.")
            return
        
        # Create weeks 1-38
        weeks_to_create = []
        for week_num in range(1, 39):  # 1-38 inclusive
            week = Week(week_number=week_num)
            weeks_to_create.append(week)
        
        # Add all weeks to the session
        db.session.add_all(weeks_to_create)
        db.session.commit()
        
        print(f"Successfully created {len(weeks_to_create)} weeks (1-38)")


if __name__ == '__main__':
    create_weeks()