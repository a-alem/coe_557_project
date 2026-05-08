FROM python:3.9-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y \
    gcc \
    build-essential \
    libffi-dev \
    libssl-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    pip==23.3.2 \
    setuptools==67.6.1 \
    wheel

RUN pip install --no-cache-dir --no-build-isolation \
    eventlet==0.30.2 \
    ryu==4.34

COPY iot_acl_controller_ryu.py /app/iot_acl_controller_ryu.py

EXPOSE 6653 8080

CMD ["ryu-manager", "iot_acl_controller_ryu.py"]