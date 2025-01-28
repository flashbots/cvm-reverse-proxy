FROM golang:1.24rc2-bullseye@sha256:236da40764c1bcf469fcaf6ca225ca881c3f06cbd1934e392d6e4af3484f6cac AS builder

ARG BINARY=proxy-client
WORKDIR /app
COPY ./ /app
RUN make build-${BINARY}

FROM gcr.io/distroless/cc-debian12:nonroot-6755e21ccd99ddead6edc8106ba03888cbeed41a
ARG BINARY
COPY --from=builder /app/build/${BINARY} /app
ENTRYPOINT [ "/app" ]
