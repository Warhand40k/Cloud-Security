FROM python:3.12-slim

WORKDIR /app
RUN pip install --no-cache-dir flask prometheus_client

COPY testbed/app.py /app/app.py

EXPOSE 8088
ENV PORT=8088
CMD ["python", "app.py"]
