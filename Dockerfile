# Single stage: the frontend has no bundler and the backend is pure Python,
# so a multi-stage build would add machinery to copy the same files twice.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000 \
    HOST=0.0.0.0 \
    SWARMS_DB=/data/swarms.db

WORKDIR /app

# Dependencies before source, so editing code does not invalidate the pip layer.
COPY pyproject.toml README.md ./
COPY swarms/ swarms/
RUN pip install --no-cache-dir ".[server,llm]"

COPY web/ web/
COPY examples/ examples/

# Validate the bundled policy at build time. A container whose policy does not
# load is one that starts and then denies everything, or worse, starts in a
# mode nobody intended.
RUN python -m swarms policy check --policy swarms/default_policy.yaml

# Run the corpus against it and fail the build on any regression, so the
# security property is a release gate rather than a number in a README.
RUN python -m swarms redteam --policy swarms/default_policy.yaml --strict --web-dir web/data

# The audit database lives on a volume: it is the record of what the system
# decided, and losing it on a redeploy defeats the point of having one.
VOLUME ["/data"]

# Non-root. This process parses attacker-authored text for a living and has no
# business being able to write to its own image.
RUN useradd --create-home --uid 10001 swarms \
    && mkdir -p /data && chown -R swarms /data /app
USER swarms

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.environ.get('PORT', '8000') + '/api/health', timeout=2)"

# Bind to every interface inside the container; the host decides what is
# published. Set SWARMS_API_KEYS and SWARMS_ENV=production before exposing it,
# or the gateway refuses to start.
CMD ["python", "-m", "swarms", "serve", "--host", "0.0.0.0"]
