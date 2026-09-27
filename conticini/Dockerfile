FROM python:3.11-slim

ENV TZ=Europe/Rome \
    PYTHONUNBUFFERED=1

RUN ln -snf /usr/share/zoneinfo/Europe/Rome /etc/localtime && echo Europe/Rome > /etc/timezone

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY templates/ templates/
COPY static/ static/

VOLUME /data

EXPOSE 8080

CMD ["python", "app.py"]
