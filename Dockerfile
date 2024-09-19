FROM python:3.12.3
ADD requirements.txt .
RUN pip install -r requirements.txt
ADD config.toml.sample .
ADD field_process.py .
ADD fsyslog.py .
CMD [ "python", "fsyslog.py" ]