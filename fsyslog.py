import socketserver
import influxdb_client
from influxdb_client.client.write_api import SYNCHRONOUS
import json
import toml
from pprint import pprint
import re

from field_process import process

CONFIG_FILE = 'config.toml'

def get_config():
    config = {}
    with open(CONFIG_FILE, 'r') as f:
        config = toml.load(f)
    return config

class Fsyslog(socketserver.StreamRequestHandler):
    
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



    def parse(self, message):

# <134>1 May 29, 2024 Kentik-Alerting kentik-notify 1000 - - {"AlarmID":"395396836","AlarmPolicyID":"284436","AlarmPolicyLabels":"","AlarmPolicyMetadataType":"Custom","AlarmPolicyName":"100 Mbps hasta 1 Gbps /31 /128 ","AlarmSeverity":"major2","AlarmSeverityLabel":"Severe","AlarmThresholdID":"607833","CompanyID":34637,"CurrentState":"alarm","Description":"Alarm for 100 Mbps hasta 1 Gbps /31 /128  Active","Dimensions":{"IP_dst_cidr_31_128":"177.234.245.104/31","Port_dst":"51513","Proto":"17"},"EndTime":"ongoing","IsActive":true,"Links":{"DashboardAlarmURL":"https://portal.kentik.com/v4/library/dashboards/49","DetailsAlarmURL":"https://portal.kentik.com/v4/alerting/a395396836"},"Metrics":{"bits":58486300},"PreviousState":"new","StartTime":"2024-05-29 03:07:57 UTC","Type":"alarm","issue":[],"statistic":{}}
        
        json_index = message.find('{')
        json_text =  message[json_index:len(message) - 1]
        json_text = json_text.replace('\\\'', '\'')
        json_text = ' '.join(json_text.splitlines())
        json_payload = json.loads(json_text)
        for key in self.config['exclude']:
            rgx = self.config['exclude'][key]
            value = self.get(json_payload, self.config['fields'][key])
            p = re.compile(rgx)
            m = p.match(str(value))
            if m:
                print(f'Message: "{message}"\nexcluded by exclude statement:\n{key} = {rgx}')
                return None
        pdata = {}
        pdata['measurement'] = self.config.measurement.name
        pdata['fields'] = {}
        self.add(json_payload, pdata['fields'], self.config['fields'], self.config['process']['fields'])
        pdata['tags'] = {}
        self.add(json_payload, pdata['tags'], self.config['tags'], self.config['process']['fields'])
        self.postprocess(pdata)
        pprint(pdata)
        p = influxdb_client.Point.from_dict(pdata)
        return p

    def postprocess(self, pdata):
        if ('postprocess' in self.config):
            for postConf in self.config['postprocess']:
                if not('match' in postConf) or not('target' in postConf):
                    print('Invalid configuration in postprocessing. Missing "match" or "target"')
                    continue
                matcher = postConf["match"]
                matchOn = pdata['fields'] if matcher['type'] == 'field' else pdata['tags']
                targetConf = postConf['target']
                p = re.compile(matcher['regex'])
                m = p.match(matchOn[matcher['name']])
                if m:
                    print('matched postprocess {matcher["name"]}')
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
            print(f'Could not parse message: {message}', err)


if __name__ == "__main__":
    config = get_config()
    HOST = config["server"]['host']
    PORT = config['server']['port']
    print(f'Listening on {HOST}:{PORT}')

    with socketserver.TCPServer((HOST, PORT), Fsyslog) as server:
        server.serve_forever()