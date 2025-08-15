# Use a Python slim base image
FROM python:3.12-slim

# Set the working directory
WORKDIR /app

# Copy requirements.txt and install Python dependencies
# We will use the python -m pip command to ensure we are using the correct pip version
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Expose the port your Flask app runs on
EXPOSE 5000

# Set the command to run the Flask application using Gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
