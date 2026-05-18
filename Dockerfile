FROM denoland/deno:alpine-2.0.0

WORKDIR /app

COPY . .

EXPOSE 3000

CMD ["run", "--allow-net", "--allow-env", "server.ts"]
