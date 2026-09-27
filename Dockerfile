FROM node:18-alpine

# Install system dependencies
RUN apk add --no-cache curl bash tzdata unzip gettext

# Download and install Xray-core directly
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then XARCH="64"; \
    elif [ "$ARCH" = "aarch64" ]; then XARCH="arm64-v8a"; \
    else XARCH="64"; fi && \
    curl -L -o /tmp/xray.zip "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-${XARCH}.zip" && \
    unzip /tmp/xray.zip -d /usr/local/bin/ xray && \
    chmod +x /usr/local/bin/xray && \
    rm -rf /tmp/xray.zip

WORKDIR /app

COPY package.json ./
RUN npm install --production

COPY . .

EXPOSE 8080

CMD ["node", "server.js"]
