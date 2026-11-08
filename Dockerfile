FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY posture_scanner ./posture_scanner
COPY examples ./examples
ENTRYPOINT ["python", "-m", "posture_scanner"]
CMD ["examples/insecure"]
