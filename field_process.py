from datetime import datetime
import time
import logging


def identity(value):
    return value

def to_unixtime(value):
    #2024-05-29 03:07:57 UTC
    # Convert date format RFC3339
    dt = datetime.strptime(value, '%Y-%m-%d %H:%M:%S %Z')
    return time.mktime(dt.timetuple())
    

processMap = {
    "identity": identity,
    "unixtime": to_unixtime,
    "int"     : int
}

def process(value, process_as):
    logging.info(f'Converting {value} as {process_as} with function {processMap[process_as]}')
    return processMap[process_as](value)
