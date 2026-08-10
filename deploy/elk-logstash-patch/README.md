# ELK 5044 Beats 入口補正(對 .18 ELK stack 的 patch)

## 為什麼要這個

CyberRange catalog 多份 YAML 標 `transport: [..., beats]`,但 `.18` ELK stack 的 `<elk-stack-dir>/docker-compose.yml` **沒有 logstash service**,而 filebeat 把 host 5044 publish 進 container 後內部沒人 listen,造成:

- 從本機 `nc 127.0.0.1:5044` succeeded(docker-proxy 接 SYN)
- 從外部 `nc 192.0.2.18:5044` refused(forward 進 container 後立刻 RST)
- catalog `transport: [beats]` 是空頭支票

## 修正方向

加一個 logstash service 作為 Beats input 接收端,維持 filebeat 繼續吃 syslog(1514/514):

```
                   ┌── 514/udp  ─→ filebeat (syslog UDP/TCP)
                   ├── 1514/tcp ─┤
.18 ELK ingress ───┼── 5044/tcp ─→ logstash (Beats lumberjack) ─→ ES
                   └── 9200/tcp ─→ elasticsearch
                       5601/tcp ─→ kibana
```

## 要動的檔案(patch 內容已備齊)

| 檔案 | 動作 |
|---|---|
| `<elk-stack-dir>/docker-compose.yml` | 加 logstash service;filebeat 的 `5044:5044` port mapping 移到 logstash |
| `<elk-stack-dir>/logstash/pipeline/cyberrange.conf`(新)| input.beats + filter.mutate + output.elasticsearch |
| `<elk-stack-dir>/logstash/config/logstash.yml`(新) | http.host / api 設定 |
| `<elk-stack-dir>/.env` | 加 `LOGSTASH_HEAP_SIZE=512m`(可選) |

具體 patch 檔見本目錄:
- `docker-compose.patch.yml` — 完整新版 compose,可整檔覆蓋(diff 清楚)
- `logstash-pipeline-cyberrange.conf` — logstash pipeline
- `logstash.yml` — logstash 自身設定

## Apply 步驟(在 .18 上手動跑)

```bash
ssh lab@192.0.2.18
cd <elk-stack-dir>

# 1. 備份現有 compose
cp docker-compose.yml docker-compose.yml.bak.$(date +%Y%m%d)

# 2. 從 lab@192.0.2.10 拉新版 patch
scp lab@192.0.2.10:~/CyberRange/deploy/elk-logstash-patch/docker-compose.patch.yml ./docker-compose.yml.new
scp lab@192.0.2.10:~/CyberRange/deploy/elk-logstash-patch/logstash-pipeline-cyberrange.conf ./logstash/pipeline/cyberrange.conf
scp lab@192.0.2.10:~/CyberRange/deploy/elk-logstash-patch/logstash.yml ./logstash/config/logstash.yml

# 3. diff 確認
mkdir -p ./logstash/pipeline ./logstash/config
diff docker-compose.yml docker-compose.yml.new

# 4. 看完 diff 沒問題再上線
mv docker-compose.yml.new docker-compose.yml
docker compose up -d logstash
docker compose ps    # 確認 logstash running, healthy

# 5. 驗證 5044 從外部可達
exit
nc -zv -w 3 192.0.2.18 5044
# 應該回 succeeded(不再 refused)

# 6. 從 lab@192.0.2.10 跑端到端驗證
ssh lab@192.0.2.10 'docker exec cyberrange-api cyberrange gen \
  --vendor fortinet --product fortios --version 7.4 --log-type traffic \
  --count 3 --rate 0 --sink tcp://192.0.2.18:1514'
# 然後反查 incoming-* index 看新一批 hits
```

## 回滾

```bash
ssh lab@192.0.2.18
cd <elk-stack-dir>
mv docker-compose.yml.bak.$(date +%Y%m%d) docker-compose.yml
docker compose up -d
docker compose stop logstash && docker compose rm -f logstash
```

## 風險評估

| 風險 | 評估 |
|---|---|
| 改 compose 期間 syslog 中斷 | ⚠️ 短(秒級)— `docker compose up -d logstash` 不會動 filebeat,但若一起重啟就會中斷 |
| logstash 吃資源 | 中 — 預設 1GB heap 不算重,可調 `LOGSTASH_HEAP_SIZE=512m` |
| pipeline.conf 設錯造成 ES 收到亂的 doc | 中 — 先用最簡 pipeline,只 forward 不 transform,風險低 |
| Kibana index pattern 對 logstash 來的 index 不認得 | 低 — pipeline 把 logstash 來源寫進 `incoming-*` 同個 index,跟 filebeat 一致 |

## 不做的事

- 不改 filebeat input(維持 syslog 吃 514/1514)
- 不動 ES / Kibana 設定
- 不改 .env 既有變數,只**新增** logstash 相關變數

## 驗證 checklist

apply 之後跑下面這串:

```bash
# 從 lab@192.0.2.10 確認 5044 通
nc -zv -w 3 192.0.2.18 5044

# 從 .18 確認 logstash listen 5044
ssh lab@192.0.2.18 'docker logs <logstash-container> 2>&1 | tail -20'
ssh lab@192.0.2.18 'docker exec <logstash-container> curl -s localhost:9600/_node/stats/pipelines'

# CyberRange 端 dispatch 試打
ssh lab@192.0.2.10 'docker exec cyberrange-api cyberrange gen \
  --vendor fortinet --product fortios --version 7.4 --log-type traffic \
  --count 5 --rate 0 --sink tcp://192.0.2.18:5044'
# (註:engine 沒 native Beats client,5044 走 raw TCP 不會被 logstash beats input 解,
#  這只能驗 logstash 接收 raw text 失敗的訊息;真要 5044 走 Beats 得另起 filebeat shipper)
```

**重要**:CyberRange engine 目前**沒有 Beats client**,5044 補上之後也不會直接被 CyberRange 用到。這個 patch 只是把 `transport: [beats]` 從空頭支票變成「有入口可以接,需要時派 filebeat shipper 來餵」。
