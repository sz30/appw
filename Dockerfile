FROM node:20-alpine3.20

WORKDIR /tmp

COPY package.json index.js index.html ./

RUN apk update && apk upgrade && \
    apk add --no-cache bash openssl curl gcompat iproute2 coreutils && \
    chmod +x index.js && \
    npm install

CMD ["node", "index.js"]