FROM python:3.12-slim

RUN useradd --create-home --uid 10001 app
WORKDIR /app
COPY --chown=app:app . .
USER app

CMD ["python", "app.py"]
