FROM ubuntu:latest
ADD app.tar.gz /app/
RUN apt-get update && apt-get install -y python3
COPY . .
EXPOSE 80
CMD ["python3", "app.py"]
