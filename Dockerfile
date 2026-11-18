FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 \
    G6_HOST=0.0.0.0 \
    G6_DB_PATH=/data/gruppe6.sqlite3 \
    G6_COOKIE_SECURE=1
WORKDIR /app
COPY server.py index.html ./
EXPOSE 8080
CMD ["python", "server.py"]
