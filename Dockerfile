FROM node:20-alpine3.20

WORKDIR /tmp

COPY package.json package-lock.json index.js index.html ./

RUN apk update && apk upgrade && \
    apk add --no-cache bash openssl curl gcompat iproute2 coreutils && \
    npm ci --omit=dev

# BuildKit 根据目标平台自动提供 TARGETARCH；只打包对应架构的二进制。
ARG TARGETARCH
RUN case "$TARGETARCH" in amd64|arm64) ;; *) echo "Unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; esac
COPY --chmod=755 ${TARGETARCH}/ /tmp/${TARGETARCH}/

CMD ["node", "index.js"]
