# Use a slim, official Python image for production-ready size and security
FROM python:3.11-slim

# Set environment variables to prevent Python from writing pyc files and buffering stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file first to utilize Docker build cache
COPY requirements.txt /app/

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire workspace module tree cleanly into the container
COPY main.py /app/
COPY cyberintel_nexus/ /app/cyberintel_nexus/

# Expose port 8080 as requested
EXPOSE 8080

# Configure the container entrypoint to launch the Uvicorn web server
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
