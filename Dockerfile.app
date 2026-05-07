FROM python:3.11-slim
WORKDIR /app
RUN pip install flask requests pyjwt --no-cache-dir
COPY app.py .
COPY templates/ templates/
COPY static/ static/
CMD ["python", "app.py"]
