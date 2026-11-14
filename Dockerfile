FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py ./
COPY gateway ./gateway
RUN useradd -r -u 10001 gateway && mkdir -p telemetry && chown gateway telemetry
USER gateway
# The gateway runs `openclaw agent --local` as a subprocess. The image does NOT include openclaw:
# install it in a derived image or mount it onto PATH, otherwise /readyz returns 503 and tasks fail.
# KIMICLAW_TOKEN, KIMICLAW_LIMIT_CONCURRENCY and GATEWAY_* come from the runtime env (never baked in).
EXPOSE 8000 8001
# Liveness: probe-port /healthz is 200 as soon as the process is up (including the ~31s hold).
# /readyz is 503 in the stock image until openclaw is present, so it is not the HEALTHCHECK target.
HEALTHCHECK CMD python -c "import urllib.request as u;u.urlopen('http://127.0.0.1:8001/healthz',timeout=3)"
CMD ["python", "-m", "gateway", "--host", "0.0.0.0", "--port", "8000"]
