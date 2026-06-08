# crowdsec-bouncer-with-ratelimit

Bouncer customizado que aplica as decisões do **CrowdSec** na borda da **GoCache CDN**
(firewall da GoCache, ação `block`), com rate limit para respeitar os limites da API.

É a peça que faz o IP banido pelo CrowdSec ser bloqueado **antes** de chegar ao
servidor de origem — sem ela, o CrowdSec detecta o ataque mas o tráfego malicioso
continua batendo no nginx/PHP do site.

---

## Arquitetura (produtor → fila em arquivo → consumidor)

Este projeto roda dentro do container Docker **`csb-gocache`** (imagem
`apiki/wphost:gocache-bouncer`). O `init.sh` sobe **dois processos**:

```
CrowdSec (LAPI)
   │  decisões de ban/unban (polling a cada 10s)
   ▼
crowdsec-custom-bouncer (Go)        ── processo 1 (binário oficial)
   │  para cada decisão executa bin_path = gocache.sh
   ▼
gocache.sh                          ── NÃO bane; só ENFILEIRA
   │  echo "add|del <IP> ..." >> /var/log/crowdsec-gocache-bouncer.log
   │  (tem um `exit 0` proposital — o curl abaixo dele é legado morto)
   ▼
/var/log/crowdsec-gocache-bouncer.log   ── fila append-only
   ▲
index.py (Python)                   ── processo 2 — ESTE REPO; é quem BANE
      faz tail -f no log e, para cada linha add/del, chama a API GoCache:
        add → POST   https://api.gocache.com.br/v1/firewall  (action[firewall]=block)
        del → DELETE https://api.gocache.com.br/v1/firewall/<hashid>
```

> **Importante:** quem efetivamente aplica o ban na GoCache é o **`index.py`**, não o
> `gocache.sh`. Ao depurar, NÃO conclua "não bane" só porque o `gocache.sh` tem um
> `exit 0` no começo — ele é apenas o produtor da fila. Valide o consumidor (ver abaixo).

### Arquivos

| Arquivo | Papel |
|---|---|
| `index.py` | Consumidor: tail -f no log, chama a API GoCache, expõe métricas Prometheus |
| `requirements.txt` | `backoff`, `ratelimit`, `requests`, `prometheus_client` |

### Variáveis de ambiente (definidas no `docker-compose.yml` / `Dockerfile` do host)

| Env | Obrigatória | Default | Descrição |
|---|---|---|---|
| `LogFileName` | sim | — | Caminho do log que o `gocache.sh` escreve e o `index.py` lê (ex: `/var/log/crowdsec-gocache-bouncer.log`) |
| `gocacheToken` | sim | — | Token da API GoCache **da conta dona daquele domínio** (cada site/cliente tem o seu) |
| `MetricsPort` | não | `9223` | Porta do exporter Prometheus embutido |

Sem `LogFileName`/`gocacheToken` o processo aborta no boot (`sys.exit(1)`).

---

## Como funciona o `index.py`

1. Abre `LogFileName` e dá `seek` no **fim** (só processa decisões novas; o histórico
   acumulado não é reaplicado — e nem precisa: o CrowdSec reemite os bans ativos).
2. Loop `while 1`: lê linha a linha. Cada linha `add <IP> ...` / `del <IP> ...` vira
   uma chamada à API GoCache.
3. **Rate limit**: `@limits(calls=45, period=30s)` + backoff exponencial — no máximo
   45 chamadas a cada 30s, para não estourar a API da GoCache.
4. **Timeout**: toda chamada HTTP usa `timeout=10s`. **Isto é crítico** (ver
   "Histórico / lição aprendida").
5. **Resiliência**: exceções de request são capturadas e logadas; uma falha de API
   nunca derruba o loop.
6. **Métricas**: expõe um endpoint Prometheus em `:MetricsPort` (degradação graciosa —
   se `prometheus_client` faltar, o bouncer roda sem telemetria).

### Logs em runtime

| Log | Conteúdo |
|---|---|
| `/var/log/crowdsec-gocache-bouncer.log` | Fila escrita pelo `gocache.sh` (decisões add/del) |
| `/var/log/crowdsec-gocache-python-script.log` | Saída do `index.py`: `add/del <IP> <Response [200]>` |

---

## Métricas Prometheus (exporter embutido)

Expostas em `http://<container>:9223/metrics`:

| Métrica | Tipo | Uso |
|---|---|---|
| `gocache_bouncer_up` | gauge | 1 = exporter no ar (heartbeat do processo) |
| `gocache_bouncer_loop_heartbeat_timestamp_seconds` | gauge | Unix time da última iteração do loop — **detecta travamento mesmo sem tráfego** |
| `gocache_bouncer_last_activity_timestamp_seconds` | gauge | Unix time da última decisão add/del processada |
| `gocache_bouncer_last_success_timestamp_seconds` | gauge | Unix time da última resposta 2xx da API GoCache |
| `gocache_bouncer_actions_total{action}` | counter | Volume de `add`/`del` processados |
| `gocache_bouncer_api_requests_total{action,result}` | counter | Chamadas à API por resultado (`success`/`error`) |
| `gocache_bouncer_api_latency_seconds{action}` | histogram | Latência das chamadas à API GoCache |

A métrica-chave para alerta é **`gocache_bouncer_loop_heartbeat_timestamp_seconds`**:
`time() - <heartbeat>` cresce indefinidamente se o loop travar.

---

## Deploy

### Forma durável (recomendada): rebuild da imagem

A imagem `apiki/wphost:gocache-bouncer` é construída a partir de um `Dockerfile` no
host que faz `git clone` deste repo + `pip install -r requirements.txt`. Portanto:

```bash
# 1. publicar as mudanças no repo
git push origin master

# 2. no host que roda o csb-gocache, rebuild + recriar o container
cd /caminho/do/compose            # onde está o docker-compose.yml do site
docker compose build csb-gocache  # refaz git clone + pip install (pega prometheus_client)
docker compose up -d csb-gocache
```

### Forma rápida (teste, sem rebuild)

Útil para validar antes de rebuildar. **Não é durável**: sobrevive a `docker restart`,
mas some em `docker rm`/rebuild a partir da imagem antiga.

```bash
# instalar a dep nova no container em runtime
docker exec csb-gocache pip install 'prometheus_client==0.20.0'
# atualizar o index.py (é bind-mount do host) e reiniciar
#   <DIR>/index.py é montado em /opt/crowdsec-bouncer-with-ratelimit/index.py
cp index.py <DIR_NO_HOST>/crowdsec-bouncer-with-ratelimit/index.py
docker restart csb-gocache
```

### Coleta pelo Prometheus

O transporte depende de onde o Prometheus roda em relação ao container:

**A) Prometheus na MESMA rede docker do container (ex: hostwatch)** — scrape direto
pelo nome do container, sem publicar porta nem mexer em firewall:

```yaml
# prometheus.yml
- job_name: 'gocache-bouncer-<host>'
  scrape_interval: '15s'
  static_configs:
    - targets: ['csb-gocache:9223']
      labels: { hostname: '<host>.apiki.com', component: 'csb-gocache', scope: 'cloud' }
```

**B) Prometheus REMOTO (ex: neofeed, scrapeado pelo Prometheus do hostwatch)** —
publicar a porta no host e liberar no firewall:

```yaml
# docker-compose.yml do site — expor a porta do exporter
  csb-gocache:
    ports:
      - "9223:9223"
```
```bash
# Security Group da instância: liberar 9223/tcp para o IP do Prometheus
#   (hostwatch privado = 30.0.1.15/32)
```
```yaml
# prometheus.yml (no hostwatch)
- job_name: 'gocache-bouncer-neofeed'
  scrape_interval: '15s'
  static_configs:
    - targets: ['30.0.3.30:9223']     # IP privado do site
      labels: { hostname: 'neofeed.com.br', component: 'csb-gocache', scope: 'site' }
```

Após editar o `prometheus.yml`: `docker restart prometheus` e verificar o target em
**up** (`/api/v1/targets` ou Grafana).

---

## Alerta no Grafana

Regra **`GOCACHE_BOUNCER_DOWN`** (folder **Tools**, grupo **WPHOST**) avisa quando o
bouncer trava ou cai:

- **Query A**: `time() - gocache_bouncer_loop_heartbeat_timestamp_seconds`
- **Condição C**: `A > 300` (5 min sem processar) → dispara
- `for: 5m`, `no_data_state: Alerting` (cobre o caso de o exporter/target sumir)
- Labels: `service=critical_bot_only` (roteia para o contact point do bot) + `severity=critical`

Para um novo host, basta o job no Prometheus com label `hostname`: o alerta é
multi-série e passa a cobrir o novo `hostname` automaticamente.

---

## Troubleshooting

### "O bouncer está vivo mas não bane" (processo zumbi)
Sintoma: container `Up`, mas `crowdsec-gocache-python-script.log` **parado** há
muito tempo.

```bash
# o log do consumidor está crescendo?
docker exec csb-gocache tail -5 /var/log/crowdsec-gocache-python-script.log
# deve mostrar linhas recentes "add/del <IP> <Response [200]>"

# o index.py está preso em I/O de socket? (diagnóstico definitivo)
PID=$(docker top csb-gocache | awk '/index.py/{print $2}')
sudo cat /proc/$PID/wchan      # "sk_wait_data" = preso esperando resposta TCP
sudo cat /proc/$PID/stack      # tcp_recvmsg -> sk_wait_data confirma

# correção imediata
docker restart csb-gocache
```

### Verificar métricas rápido
```bash
docker exec csb-gocache python3 -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:9223/metrics',timeout=5).read().decode())" | grep '^gocache_bouncer'
```

### Confirmar que está banindo na GoCache
As linhas `<Response [200]>` no `python-script.log` indicam aceite da API. `4xx/5xx`
indica token inválido/expirado ou problema na API.

---

## Histórico / lição aprendida

- **2026-05 → 2026-06 (neofeed.com.br):** o `index.py` ficou **travado ~1 mês** —
  processo vivo, mas parado em `sk_wait_data`. Causa: `requests.post/delete` **sem
  `timeout`** numa chamada que a API GoCache não respondeu; o loop bloqueou e nunca
  mais leu a fila (≈51 MB de bans acumulados sem aplicar). A borda ficou cega e bots
  (ex: AwarioBot) chegaram inteiros ao origin, saturando o PHP.
- **Correções (commits):**
  - `563bb57` — `timeout=10` em todas as chamadas + `try/except` (request lenta nunca
    mais trava o loop).
  - `37fb8f3` — exporter Prometheus embutido + alerta `GOCACHE_BOUNCER_DOWN`, para
    detectar proativamente "vivo mas parado" (não há healthcheck nativo para isso).
- **Regra de ouro:** toda chamada HTTP em loop crítico precisa de `timeout`; e
  "container Up" não é prova de funcionamento — valide o heartbeat/consumidor.
