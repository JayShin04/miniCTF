FROM python:3.11-slim
WORKDIR /app
RUN pip install flask requests pyjwt --no-cache-dir
RUN pip install flask requests python-dotenv --no-cache-dir
COPY app.py .
COPY robots.txt .
COPY templates/ templates/
COPY static/ static/
CMD ["python", "app.py"]
