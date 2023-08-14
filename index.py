from ratelimit import limits, RateLimitException
from backoff import on_exception, expo
import time, os, base64, requests, sys

try:  
   os.environ["LogFileName"]
   os.environ["gocacheToken"]
except KeyError: 
   print("Não foi definido nome do log a ser escutado ou gocache Token")
   sys.exit(1)

filename = os.environ['LogFileName']
file = open(filename,'r')

#Find the size of the file and move to the end
st_results = os.stat(filename)
st_size = st_results[6]
file.seek(st_size)


THIRTY_SECONDS = 30   # 45 hits max every 30 seconds
@on_exception(expo, RateLimitException, max_tries=8)
@limits(calls=45, period=THIRTY_SECONDS)
def call_api(line):
    if line is  None:
        return

    l = line.split(" ")
    if l[1] is not None:
        if 'add' == l[1]:
            headers = {
                'GoCache-Token': os.environ['gocacheToken'],
            }
            payload = {
                'match[ip_address]': l[2],
                'action[firewall]': 'block',
            }
            response = requests.post('https://api.gocache.com.br/v1/firewall', data=payload, headers=headers)
        if 'del' == l[1]:
            headers = {
                'GoCache-Token': os.environ['gocacheToken'],
            }
            hashID='ip_address-default|ip_address|'+l[2]+'|u'
            base64_bytes=base64.b64encode(hashID.encode('ascii'))
            HASHCODE = base64_bytes.decode('ascii')
            response = requests.delete('https://api.gocache.com.br/v1/firewall/'+HASHCODE, headers=headers)
    
    return response 

while 1:
    where = file.tell()
    line = file.readline()
    if not line:
        time.sleep(1)
        file.seek(where)
    else:
        print(call_api(line)) # already has newline