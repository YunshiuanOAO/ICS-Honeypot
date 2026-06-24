FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir paho-mqtt
COPY gateway.py streetlight_data.json ./
EXPOSE 15566
CMD ["python", "-u", "gateway.py"]
