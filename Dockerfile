FROM rust:1.75

RUN mkdir /app
WORKDIR /app
COPY . .

RUN apt-get install -y nodejs npm

RUN npm install
RUN npx tailwindcss -i ./styles/input.css -o ./styles/site.css

RUN cargo install sqlx-cli
RUN cargo install --path .

CMD ["club"]