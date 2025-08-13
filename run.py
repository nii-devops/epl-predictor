
from app import create_app
from app.models import db, Week, Season
import os

app = create_app()

def ensure_default_data():
    """Ensure default data exists in the database"""
    with app.app_context():
        # Create tables if they don't exist
        db.create_all()
        
        # Create weeks 1-38 if they don't exist
        existing_weeks = Week.query.count()
        if existing_weeks == 0:
            print("Creating EPL weeks 1-38...")
            weeks_to_create = []
            for week_num in range(1, 39):
                week = Week(week_number=week_num)
                weeks_to_create.append(week)
            
            db.session.add_all(weeks_to_create)
            db.session.commit()
            print(f"Created {len(weeks_to_create)} weeks")
        

# Only run setup if we're starting the server (not during migrations)
if __name__ == '__main__':
    ensure_default_data()
    print("🚀 Starting EPL Predictions App...")
    app.run(debug=True, host='0.0.0.0', port=5000)

# For production/deployment, you might want to run this check
# even when imported (uncomment the line below)
# ensure_default_data()



"""

from app import create_app

app = create_app()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

"""

