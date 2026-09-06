FROM python:3.12-alpine@sha256:d09d15e60962ca365d1cd544a48773bac9d33f2fb1b00f2aa0deec78ade7dc31
COPY requirements.txt /app/requirements.txt
RUN python -m pip install --no-cache-dir --upgrade pip==26.1.2 && \
    pip install --no-cache-dir --requirement /app/requirements.txt
RUN mkdir /data && chown 65532:65532 /data && chmod 700 /data
COPY app.py body_limit.py /app/
RUN mv /app/app.py /app/standby_auth.py
USER 65532:65532
CMD ["uvicorn", "standby_auth:app", "--app-dir", "/app", "--host", "0.0.0.0", "--port", "8080", "--no-server-header", "--no-access-log"]
