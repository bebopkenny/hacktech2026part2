FROM python:3.11-slim

# git required for clone_repo; semgrep installed separately so layer is cached
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*
RUN pip install semgrep

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
