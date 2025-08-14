# Example Dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 8080

# Command to run the app with Gunicorn
# "main:app" assumes main.py exists and defines `app = create_app()`
CMD ["gunicorn", "--bind", "0.0.0.0:$PORT", "--workers", "2", "--threads", "4", "run:app"]