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
# KIMICLAW_TOKEN and GATEWAY_* come from the runtime env (never baked in).
EXPOSE 8000
# Liveness only: /healthz is public. /readyz is not used here because it is 503 until openclaw is present.
HEALTHCHECK CMD python -c "import urllib.request as u;u.urlopen('http://127.0.0.1:8000/healthz',timeout=3)"
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
