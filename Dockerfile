FROM python:3.12-slim
RUN useradd -u 10001 -m agent
WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
COPY runbooks ./runbooks
RUN pip install --no-cache-dir .
USER 10001
ENTRYPOINT ["k8s-agent"]
