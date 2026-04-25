FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl git wget \
    && rm -rf /var/lib/apt/lists/*

# Install solc compiler 
RUN pip install --no-cache-dir solc-select && \
    solc-select install 0.8.20 && \
    solc-select install 0.8.0  && \
    solc-select install 0.7.6  && \
    solc-select use 0.8.20

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PORT=8000
EXPOSE 8000

CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT}"]
