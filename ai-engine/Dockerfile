FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY *.py .

# Create models directory
RUN mkdir -p models

# Run the AI engine
CMD ["python", "main.py"]
