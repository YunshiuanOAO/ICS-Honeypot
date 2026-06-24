FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir pymongo
COPY socket_server.py streetlight_data.json* ./
EXPOSE 15567 15568
CMD ["python", "-u", "socket_server.py"]
