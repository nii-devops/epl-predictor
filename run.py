
from app import create_app
from app.models import db, Week, Season
import os

app = create_app()

        

# Only run setup if we're starting the server (not during migrations)
if __name__ == '__main__':
    print("🚀 Starting EPL Predictions App...")
    app.run(debug=True, host='0.0.0.0', port=5050)


