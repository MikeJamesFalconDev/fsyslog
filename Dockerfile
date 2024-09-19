FROM python:3.12.3
WORKDIR /opt/fsyslog
USER fsyslog
ADD requirements.txt .
RUN pip install -r requirements.txt
ADD config.toml.sample .
ADD field_process.py .
ADD fsyslog.py .
EXPOSE 5140
CMD [ "python", "fsyslog.py" ]