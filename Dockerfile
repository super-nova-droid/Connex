# Use a Python base image
FROM python:3.12-alpine

# Install system dependencies for Pillow and other common libraries
RUN apk add --no-cache \
    build-base \
    zlib-dev \
    jpeg-dev \
    freetype-dev \
    lcms2-dev

# Set the working directory
WORKDIR /app

# Copy requirements.txt and install Python dependencies
COPY requirements.txt .
RUN python -m venv /opt/venv && \
    . /opt/venv/bin/activate && \
    pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Expose the port your Flask app runs on
EXPOSE 5000

# Set the command to run the Flask application
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
