FROM python:3.9

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl unzip xvfb libxi6 libgconf-2-4 gnupg && \
    curl -sSL https://dl.google.com/linux/linux_signing_key.pub | apt-key add - && \
    echo "deb http://dl.google.com/linux/chrome/deb/ stable main" | tee /etc/apt/sources.list.d/google-chrome.list && \
    apt-get update && \
    apt-get install -y google-chrome-stable && \
    curl https://chromedriver.storage.googleapis.com/`curl -sS chromedriver.storage.googleapis.com/LATEST_RELEASE`/chromedriver_linux64.zip -o /tmp/chromedriver.zip && \
    unzip /tmp/chromedriver.zip chromedriver -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/chromedriver

WORKDIR /app

COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY api ./api
EXPOSE 5000

CMD ["python", "./api/app.py"]
