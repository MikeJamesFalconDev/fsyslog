FROM python:3.12.3
RUN mkdir -p /opt/fsyslog
RUN useradd -d /opt/fsyslog -s /bin/sh fsyslog
RUN chown fsyslog:fsyslog /opt/fsyslog
WORKDIR /opt/fsyslog
USER fsyslog
ADD requirements.txt .
RUN pip install -r requirements.txt
RUN mkdir config
ADD config/config.toml.sample config/.
ADD config/logging.toml
RUN mkdir logs
ADD field_process.py .
ADD fsyslog.py .
EXPOSE 5140
CMD [ "python", "fsyslog.py" ]
