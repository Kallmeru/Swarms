# Single-stage on purpose: there is nothing to build. The frontend has no
# bundler and the backend is pure Python, so a multi-stage image would add
# machinery to copy the same files into the same place.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000

WORKDIR /app

# Dependencies first, so a code change does not invalidate the pip layer.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY core/ core/
COPY swarm/ swarm/
COPY attack_lab/ attack_lab/
COPY benchmark/ benchmark/
COPY server/ server/
COPY web/ web/
COPY Demo.py .

# Generate the benchmark data the site reads, at build time, so the image is
# self-contained and /api/benchmark answers on first boot. It also fails the
# build if any attack gets through, which makes the security property a
# release gate rather than a number in a README.
RUN python -m benchmark.run_benchmark --strict --quiet

# Non-root: the container runs attacker-authored text through a parser, and
# there is no reason for that process to be able to write to its own image.
RUN useradd --create-home --uid 10001 swarms && chown -R swarms /app
USER swarms

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD python -c "import urllib.request,os,sys; sys.exit(0 if urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"PORT\",8000)}/api/health', timeout=2).status==200 else 1)"

CMD ["python", "-m", "server"]
