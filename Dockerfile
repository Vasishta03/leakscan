FROM python:3.15-alpine AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY scanner ./scanner
COPY leakscan ./leakscan
RUN pip wheel --no-cache-dir --wheel-dir /wheels .

FROM python:3.15-alpine
LABEL org.opencontainers.image.source="https://github.com/Vasishta03/leakscan" \
      org.opencontainers.image.description="Find leaked API keys and secrets in code, git history, images and packages" \
      org.opencontainers.image.licenses="MIT"
RUN apk add --no-cache git \
    && adduser -D -u 10001 leakscan
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels \
    && git config --system --add safe.directory '*'
USER leakscan
WORKDIR /src
ENTRYPOINT ["leakscan"]
CMD ["scan", ".", "--no-progress"]
