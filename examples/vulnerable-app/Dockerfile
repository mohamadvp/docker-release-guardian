FROM python:latest

ENV API_TOKEN=super-secret-value
ADD https://example.com/install.sh /tmp/install.sh

WORKDIR /app
COPY . .
RUN pip install -r requirements.txt

CMD ["python", "app.py"]
