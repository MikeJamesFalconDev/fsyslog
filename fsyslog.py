import os
import socketserver
import influxdb_client
from influxdb_client.client.write_api import SYNCHRONOUS
import json
import toml
import logging
import logging.config
from pprint import pformat
import re

from field_process import process
# from email_sender import send_error

CONFIG_FOLDER = 'config'
CONFIG_FILE = f'{CONFIG_FOLDER}/config.toml'
LOGGING_CONFIG_FILE = f'{CONFIG_FOLDER}/logging.toml'

arbor_tms_mitigation_regex = re.compile(r".*<\d+>[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+\s+pfsp:\s+(?P<message_type>[^']+)\s'Alert\s+(?P<AlarmID>\d+)[^']*'\s+(started\sat\s(?P<StartTime>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\s+[A-Z]{3}))?(stopped\sat\s(?P<EndTime>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\s+[A-Z]{3}))?, leader\s+(?P<leader>[^,^\s]+), managed object\s+'(?P<client>[^']+)'\s+\(\d+\),\s+first diversion prefix (?P<first_diversion_prefix>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+)")
arbor_host_detection_regex = re.compile(r".*<\d+>[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+\s+pfsp:\s+(?P<message_type>[^#]+)\s#(?P<AlarmID>[^,]+),\s+start\s(?P<StartTime>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\s+[A-Z]{3}),\s+duration\s+(?P<duration>\d+)(,\s+stop\s(?P<EndTime>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\s+[A-Z]{3}))?(,\s+direction\s+(?P<direction>[^,]+),\s+host\s+(?P<host>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}), signatures\s+\((?P<signatures>[^)]+)\),\s+impact\s+(?P<impact>[^,]+))?,\s+importance\s(?P<importance>[^,]+),\s+managed_objects\s+\((?P<client>[^)]+)\)(, is now done)?(,\s+\(parent\s+managed\s+object\s+(?P<parent_managed_object>[^)]+)\))?(,\s+impact\s+(?P<impact2>.*))?")
wangard_tms_mitigation_regex = re.compile(r".*<\d+>[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+\s+:\s+type=(?P<message_type>[^,]+),host=(?P<host>[^,]+),alarmid=(?P<alarmid>\d+),prefix=(?P<prefix>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}),description=(?P<description>[^,]+),anomaly=(?P<anomaly>[^,]+),peak_pkts=(?P<peak_pkts>\d+),peak_bits=(?P<peak_bits>\d+),from=(?P<from>\d{4}-\d{2}-\d{2}\s+\d{1,2}:\d{1,2}:\d{1,2}),until=(?P<until>\d{4}-\d{2}-\d{2}\s+\d{1,2}:\d{1,2}:\d{1,2}),duration=(?P<duration_modifier>[^\d]*)(?P<duration>\d+)(?P<duration_unit>[A-Za-z]+)")

def get_config():
    config = {}
    with open(CONFIG_FILE, 'r') as f:
        config = toml.load(f)
    logging_config = {}
    with open(LOGGING_CONFIG_FILE, 'r') as f:
        logging_config = toml.load(f)
        logging_config["version"] = 1
        logging.config.dictConfig(logging_config)
    return config

class Fsyslog():
    
    def configure(self):
        self.config = get_config()


    def get(self, payload, kpath):
        value = payload
        kp = kpath.split('/')
        for regex in kp:
            found = False
            p = re.compile(regex)
            for key in value:
                m = p.match(key)
                if m:
                    value = value[key]
                    found = True
                    break
            if not(found):
                return None
        return value

    def add(self, payload, values, mapping, process_as):
        for name in mapping:
            payload_key = mapping[name]
            value = self.get(payload, payload_key)
            if value:
                values[name] = process(value, process_as[name] if name in process_as else 'identity') 

    def parse_kentik(self, message):
# Kentik <134>1 May 29, 2024 Kentik-Alerting kentik-notify 1000 - - {"AlarmID":"395396836","AlarmPolicyID":"284436","AlarmPolicyLabels":"","AlarmPolicyMetadataType":"Custom","AlarmPolicyName":"100 Mbps hasta 1 Gbps /31 /128 ","AlarmSeverity":"major2","AlarmSeverityLabel":"Severe","AlarmThresholdID":"607833","CompanyID":34637,"CurrentState":"alarm","Description":"Alarm for 100 Mbps hasta 1 Gbps /31 /128  Active","Dimensions":{"IP_dst_cidr_31_128":"177.234.245.104/31","Port_dst":"51513","Proto":"17"},"EndTime":"ongoing","IsActive":true,"Links":{"DashboardAlarmURL":"https://portal.kentik.com/v4/library/dashboards/49","DetailsAlarmURL":"https://portal.kentik.com/v4/alerting/a395396836"},"Metrics":{"bits":58486300},"PreviousState":"new","StartTime":"2024-05-29 03:07:57 UTC","Type":"alarm","issue":[],"statistic":{}}
        if not('{' in message):
            return {}
        json_index = message.find('{')
        json_text =  message[json_index:len(message) - 1]
        json_text = json_text.replace('\\\'', '\'')
        json_text = ' '.join(json_text.splitlines())
        json_payload = json.loads(json_text)
        return json_payload

    def parse_arbor(self, message):
# Arbor  <125>Oct  9 15:35:10 pfsp: TMS mitigation 'Alert 10696181 IPv4 Auto-Mitigation' started at 2024-10-09 09:35:09 CST, leader arbui2.opentransit.net, managed object 'ITELLUM' (5729), first diversion prefix 190.61.60.251/32
        m = arbor_tms_mitigation_regex.match(message)
        if m:
            logging.info('Arbor TMS Mitigation message')
            d = m.groupdict()
        else:
            m = arbor_host_detection_regex.match(message)
            if m:
                logging.info('Arbor Host Detection message')
                d = m.groupdict()
                # Due to inconsistend ordering in the message, impact appears before or after other fields. This force me to create a second impact field. The following code puts it back under impact.
                if 'impact2' in d:
                    d['impact'] = d['impact2']
                    del d['impact2']
            else:
                logging.warning('Arbor regex not matched')
                return {}
        return d

    def parse_fortigate(self, message):
# <189>1 2025-06-04T15:29:06Z FortiGate-1800F-GUA - - - - eventtime=1749050946187327342 tz="-0600" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=2803:1040:1802:3b4b:7ca4:6cd6:e0de:714d srcport=58769 srcintf="port36" srcintfrole="wan" dstip=2803:e880:8111:1b:: dstport=53 dstintf="ZONA-DNS" dstintfrole="lan" sessionid=395601599 proto=17 action="accept" policyid=430 policytype="policy" poluuid="bd93d5a2-0bdf-51ef-d488-97112a346de5" policyname="SGACTNICASAIPV6" srccountry="Nicaragua" dstcountry="Guatemala" service="DNS" trandisp="noop" duration=30 sentbyte=92 rcvdbyte=197 sentpkt=1 rcvdpkt=1 appcat="unscanned" dsthwvendor="HP" masterdstmac="94:18:82:68:22:35" dstmac="94:18:82:68:22:35" dstserver=1
        message = str(message)
        d = {}
        start_str = '- - - -'
        pos = message.find(start_str)
        if pos >= 0:
            key_values = message[pos + len(start_str):].strip()
            # Use regex to properly handle quoted values and spaces
            pattern = r'(\w+)\s*=\s*("([^"]*)"|([^\s]+))'
            matches = re.findall(pattern, key_values)
            for match in matches:
                key = match[0]
                value = match[2] if match[2] else match[3]
                d[key] = value
        else:
            return d
        return d

    def parse(self, message):

        json_payload = self.parse_arbor(message)
        logging.info(f'Message {message}')

        if not(json_payload):
            json_payload = self.parse_kentik(message)
        if not(json_payload):
            json_payload = self.parse_fortigate(message)
        if not(json_payload):
            logging.warning('Not Kentik, Arbor or Fortigate format, not parsing!!!')
            json_payload = {}
        for key in self.config['exclude']:
            rgx = self.config['exclude'][key]
            # value = self.get(json_payload, self.config['fields'][key])
            value = self.get(json_payload, key)
            logging.info(f'Value to compare for exclusion: {value}')
            p = re.compile(rgx)
            m = p.match(str(value))
            if m:
                logging.info(f'Message: "{message}"\nexcluded by exclude statement:\n{key} = {rgx}')
                return None
        pdata = {}
        pdata['measurement'] = self.config['measurement']['name']
        pdata['fields'] = {}
        self.add(json_payload, pdata['fields'], self.config['fields'], self.config['process']['fields'])
        pdata['tags'] = {}
        self.add(json_payload, pdata['tags'], self.config['tags'], self.config['process']['fields'])
        self.postprocess(pdata)
        logging.info(pformat(pdata))
        p = influxdb_client.Point.from_dict(pdata)
        return p

    def postprocess(self, pdata):
        if ('postprocess' in self.config):
            for postConf in self.config['postprocess']:
                if not('match' in postConf) or not('target' in postConf):
                    logging.info('Invalid configuration in postprocessing. Missing "match" or "target"')
                    continue
                matcher = postConf["match"]
                matchOn = pdata['fields'] if matcher['type'] == 'field' else pdata['tags']
                targetConf = postConf['target']
                p = re.compile(matcher['regex'])
                m = p.match(matchOn[matcher['name']])
                if m:
                    logging.info('matched postprocess {matcher["name"]}')
                    targetOn = pdata['fields'] if targetConf['type'] == 'field' else pdata['tags']
                    target = targetConf['name'] if targetConf['name'] else matcher['name']
                    targetOn[target] = targetConf['value']


    def handle(self):
        self.configure()
        client = influxdb_client.InfluxDBClient(url=self.config['influx']['uri'], token=self.config['influx']['token'], org=self.config['influx']['org'])
        write_api = client.write_api(write_options=SYNCHRONOUS)
        message = self.rfile.readline().strip()
        #self.client_address[0]))
        #self.wfile.write(self.data.upper())
        try:
            point = self.parse(str(message))
            if point == None:
                return
            write_api.write(bucket=self.config['influx']["bucket"], org=self.config['influx']["org"], record=point)
        except Exception as err:
            logging.error('Could not parse message: ' + str(message) + '\n' + str(err))
            # logging.exception(err)
            # TODO threshold de eventos para mandar mail.
            # send_error(err,self.config['email'])

class FsyslogTCP(Fsyslog, socketserver.StreamRequestHandler):
    pass

class FsyslogUDP(Fsyslog, socketserver.DatagramRequestHandler):
    pass

if __name__ == "__main__":
    config = get_config()
    HOST = config["server"]['host']
    PORT = config['server']['port']
    processid = os.fork()
    if processid == 0 :
        logging.info(f'Listening on UDP {HOST}:{PORT}')
        with socketserver.UDPServer((HOST, PORT), FsyslogUDP) as server:
            server.serve_forever()

    else:
        logging.info(f'Listening on TCP {HOST}:{PORT}')
        with socketserver.TCPServer((HOST, PORT), FsyslogTCP) as server:
            server.serve_forever()
