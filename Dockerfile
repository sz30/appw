FROM node:20-alpine3.20

WORKDIR /tmp

COPY package.json package-lock.json index.js index_lite.js index.html ./

RUN apk update && apk upgrade && \
    apk add --no-cache bash openssl curl gcompat iproute2 coreutils && \
    npm ci --omit=dev

CMD ["node", "index.js"]
