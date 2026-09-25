FROM ruby:3.0.7

WORKDIR /app

COPY Gemfile Gemfile.lock ./
RUN bundle install

COPY . .

EXPOSE 3000
CMD ["sh", "-c", "bin/rails db:prepare db:seed && bin/rails server -b 0.0.0.0 -p 3000"]
