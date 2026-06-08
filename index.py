from ratelimit import limits, RateLimitException
from backoff import on_exception, expo
import time, os, base64, requests, sys

print("initing::::::::::::::::")
try:
   os.environ["LogFileName"]
   os.environ["gocacheToken"]
except KeyError:
   print("Não foi definido nome do log a ser escutado ou gocache Token")
   sys.exit(1)

# ---------------------------------------------------------------------------
# Metricas Prometheus (opcional). Se prometheus_client nao estiver instalado,
# o bouncer segue funcionando normalmente — a telemetria NUNCA pode derrubar a
# funcao de banir. Porta exposta em METRICS_PORT (default 9223), scrapeada pelo
# Prometheus (ex: gocache_bouncer_up, _last_activity_timestamp_seconds, etc).
# ---------------------------------------------------------------------------
METRICS_ENABLED = False
try:
    from prometheus_client import start_http_server, Gauge, Counter, Histogram
    METRICS_PORT = int(os.environ.get("MetricsPort", "9223"))

    M_UP = Gauge('gocache_bouncer_up', 'Bouncer GoCache no ar (heartbeat do processo)')
    M_LAST_ACTIVITY = Gauge('gocache_bouncer_last_activity_timestamp_seconds',
                            'Unix time da ultima linha de decisao processada (add/del)')
    M_LAST_SUCCESS = Gauge('gocache_bouncer_last_success_timestamp_seconds',
                           'Unix time da ultima resposta 2xx da API GoCache')
    M_LOOP_HEARTBEAT = Gauge('gocache_bouncer_loop_heartbeat_timestamp_seconds',
                             'Unix time da ultima iteracao do loop principal (detecta travamento)')
    M_ACTIONS = Counter('gocache_bouncer_actions_total',
                        'Total de acoes processadas do log', ['action'])
    M_API = Counter('gocache_bouncer_api_requests_total',
                    'Total de chamadas a API GoCache', ['action', 'result'])
    M_LATENCY = Histogram('gocache_bouncer_api_latency_seconds',
                          'Latencia das chamadas a API GoCache', ['action'])

    start_http_server(METRICS_PORT)
    M_UP.set(1)
    METRICS_ENABLED = True
    print("metrics::exporter ouvindo em :%d" % METRICS_PORT)
except Exception as e:
    print("metrics::desabilitado (%r) — bouncer segue sem telemetria" % e)

def _now():
    return time.time()

filename = os.environ['LogFileName']
file = open(filename,'r')

#Find the size of the file and move to the end
st_results = os.stat(filename)
st_size = st_results[6]
file.seek(st_size)

# Timeout (segundos) para chamadas a API GoCache. Sem isto, um request pendurado
# bloqueia o loop indefinidamente (sk_wait_data) e o bouncer para de aplicar bans.
HTTP_TIMEOUT = 10

THIRTY_SECONDS = 30   # 45 hits max every 30 seconds
@on_exception(expo, RateLimitException, max_tries=8)
@limits(calls=45, period=THIRTY_SECONDS)
def call_api(line):
    if line is None:
        return

    l = line.split(" ")
    if len(l) < 3:
        return
    action = l[1]
    ip = l[2]
    if METRICS_ENABLED:
        M_LAST_ACTIVITY.set(_now())
        if action in ('add', 'del'):
            M_ACTIONS.labels(action=action).inc()
    response = None
    started = _now()
    try:
        if 'add' == action:
            headers = {
                'GoCache-Token': os.environ['gocacheToken'],
            }
            payload = {
                'match[ip_address]': ip,
                'action[firewall]': 'block',
            }
            response = requests.post('https://api.gocache.com.br/v1/firewall', data=payload, headers=headers, timeout=HTTP_TIMEOUT)
        if 'del' == action:
            headers = {
                'GoCache-Token': os.environ['gocacheToken'],
            }
            hashID='ip_address-default|ip_address|'+ip+'|u'
            base64_bytes=base64.b64encode(hashID.encode('ascii'))
            HASHCODE = base64_bytes.decode('ascii')
            response = requests.delete('https://api.gocache.com.br/v1/firewall/'+HASHCODE, headers=headers, timeout=HTTP_TIMEOUT)
    except requests.exceptions.RequestException as e:
        print("ERRO", action, ip, repr(e))
        if METRICS_ENABLED and action in ('add', 'del'):
            M_API.labels(action=action, result='error').inc()
        return None
    if METRICS_ENABLED and action in ('add', 'del'):
        M_LATENCY.labels(action=action).observe(_now() - started)
        ok = response is not None and 200 <= response.status_code < 300
        M_API.labels(action=action, result='success' if ok else 'error').inc()
        if ok:
            M_LAST_SUCCESS.set(_now())
    print(action, ip, response)
    return response

while 1:
    if METRICS_ENABLED:
        M_LOOP_HEARTBEAT.set(_now())
    where = file.tell()
    line = file.readline()
    if not line:
        time.sleep(1)
        file.seek(where)
    else:
        try:
            call_api(line) # already has newline
        except Exception as e:
            print("LOOP-ERRO", repr(e))
