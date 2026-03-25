FROM python:3.13-slim

RUN echo "deb http://deb.debian.org/debian bookworm non-free" >> /etc/apt/sources.list.d/non-free.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends unrar p7zip-full build-essential && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p uploads

EXPOSE 5000

ENV FLASK_APP=app.py
ENV PYTHONUNBUFFERED=1

CMD ["python", "app.py"]
