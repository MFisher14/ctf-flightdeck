# syntax=docker/dockerfile:1
FROM python:3.12-slim AS build
ARG PIP_TOKEN=pip_EXAMPLE_token
WORKDIR /src
COPY . /src
RUN pip install --no-cache-dir -r requirements.txt \
    && curl -fsSL https://downloads.example.com/agent.sh | sh

FROM gcr.io/distroless/python3
ENV APP_ENV=production API_KEY="key_EXAMPLE_456"
COPY --from=build /src /app
WORKDIR /app
USER 65532
EXPOSE 8443/tcp
ENTRYPOINT ["python", "/app/main.py"]
CMD ["--port", "8443"]
