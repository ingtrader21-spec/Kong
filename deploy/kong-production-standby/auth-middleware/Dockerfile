FROM python:3.12-alpine@sha256:d09d15e60962ca365d1cd544a48773bac9d33f2fb1b00f2aa0deec78ade7dc31
RUN python -m pip install --no-cache-dir --upgrade pip==26.1.2 && \
    pip install --no-cache-dir \
    fastapi==0.141.1 \
    uvicorn==0.35.0 \
    'PyJWT[crypto]==2.13.0' \
    'psycopg[binary]==3.2.9'
RUN mkdir /data && chown 65532:65532 /data && chmod 700 /data
COPY app.py body_limit.py /app/
RUN mv /app/app.py /app/standby_auth.py
USER 65532:65532
CMD ["uvicorn", "standby_auth:app", "--app-dir", "/app", "--host", "0.0.0.0", "--port", "8080", "--no-server-header", "--no-access-log"]
