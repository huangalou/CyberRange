# 部署 CyberRange 到 .202(`bas.example.com`)

> 依既定 reverse-proxy sidecar pipeline 設計,把 CyberRange 掛成 `<reverse-proxy>` 底下的一個 vhost。
>
> **存取面**:WAN 端走 FortiGate IP allowlist + SSL VPN;LAN 端直接走 .202:443。

## 對外存取規則

| 來源 | 允許? | 機制 |
|---|---|---|
| 對外公網 IP(示例)`203.0.113.79` | ✅ | FortiGate WAN→.202:443 policy 限定 source IP |
| SSL VPN 撥回 | ✅ | 已有 |
| 其他公網 | ❌ | FortiGate default deny |
| LAN 內 | ✅ | 直連 .202:443 |

> 應用層另有 HTTP Basic Auth(預留之後加 OTP),即使網路層失守也擋一層。

---

## 一次性前置(只做一次)

### 1. Cloudflare DNS

```
Type: A
Name: bas
Value: <your home WAN IP>
Proxy: DNS only(關小雲;Let's Encrypt webroot challenge 才能通)
TTL: Auto
```

### 2. FortiGate WAN→.202:443 policy

如尚未為 .202 開 443 → 走 FortiGate Web UI 或 CLI,加入 source IP allowlist:

```
config firewall address
  edit "office-pub"
    set subnet 203.0.113.79 255.255.255.255
  next
end

config firewall vip
  edit "vip-bas-https"
    set extip <your home WAN IP>
    set extintf "wan1"
    set mappedip "192.0.2.202"
    set portforward enable
    set extport 443
    set mappedport 443
  next
end

config firewall policy
  edit 0
    set name "wan-to-bas-https"
    set srcintf "wan1"
    set dstintf "internal"
    set srcaddr "office-pub"
    set dstaddr "vip-bas-https"
    set service "HTTPS"
    set action accept
    set logtraffic all
    set nat disable
  next
end
```

> 既有 SSL VPN policy 不動,VPN 撥回後從 internal 段直連 .202:443。

### 3. 把 repo clone 到 .202

```bash
ssh lab@192.0.2.202
cd ~
git clone git@github.com:huangalou/CyberRange.git
cd CyberRange
```

### 4. 產 Basic Auth bcrypt hash + 寫 .env

```bash
# 在 .202 上(假設 system Python 有 bcrypt;若無,docker run --rm python:3.12-slim 跑)
python3 -c "import bcrypt;print(bcrypt.hashpw(b'<choose-strong-password>', bcrypt.gensalt()).decode())"

cp .env.example .env
# 編輯 .env 把 CYBERRANGE_BASIC_PASS_BCRYPT 換成上面那串
# 確認 CYBERRANGE_ALLOWED_SINK_HOSTS=192.0.2.10,192.0.2.18
```

### 5. certbot 取 cert

走 `<reverse-proxy>` 既有 certbot-webroot(依既定慣例):

```bash
sudo certbot certonly --webroot \
  -w /home/lab/certbot-webroot \
  -d bas.example.com
```

### 6. `<reverse-proxy>` vhost 註冊

```bash
cd ~/<reverse-proxy>
# 編 generate-conf.sh,在 VHOSTS 列尾加 "bas"
sed -i 's/VHOSTS=(.*)/&/' generate-conf.sh   # 看一眼現況
```

手動編 `generate-conf.sh`,把 `VHOSTS=(... <other-vhost-1> <other-vhost-2>)` 加成 `VHOSTS=(... <other-vhost-1> <other-vhost-2> bas)`,然後:

```bash
./generate-conf.sh
docker compose down && docker compose up -d   # restart 不會清舊 conf,所以 down/up
docker exec <reverse-proxy> nginx -t          # 驗 config 語法
```

> 為什麼 `down/up` 而非 `restart`:OWASP `modsec-crs:nginx-alpine` entrypoint 只 render 不 cleanup,`restart` 會留舊 conf。

### 7. 確認 modsec template 有 `/api/` path-based proxy

`generate-conf.sh` 預設一個 vhost 一個 upstream,bas 需要兩個(`/api/` → api,其他 → web)。在 generate-conf.sh 為 `bas` 寫專用 template 或手動補 `bas.example.com.conf` 落地檔。建議寫專用 template:

```nginx
# bas.example.com — CyberRange (web + api 共 vhost)
server {
    listen 80;
    server_name bas.example.com;
    location /.well-known/acme-challenge/ { root /var/www/certbot; }
    location / { return 301 https://$host$request_uri; }
}

server {
    listen 443 ssl;
    http2 on;
    server_name bas.example.com;

    ssl_certificate     /etc/letsencrypt/live/bas.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/bas.example.com/privkey.pem;

    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsecurity.d/setup.conf;

    # API 後端(走 gateway-net,以容器名連)
    location /api/ {
        proxy_pass http://cyberrange-api:8001/;   # 注意尾斜線:剝掉 /api 前綴
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For  $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # Web 前端
    location / {
        proxy_pass http://cyberrange-web:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For  $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

> CyberRange compose 加入 `gateway-net`(`<reverse-proxy>` 跟所有 backend 容器共用),所以 `<reverse-proxy>` 可以直接用容器名 `cyberrange-api` / `cyberrange-web` 連線,不需暴露 host port。

### 8. 啟動 CyberRange container

```bash
cd ~/CyberRange
docker compose up -d --build
docker compose ps           # 看 cyberrange-api / cyberrange-web 是否 running
docker compose logs -f --tail=50 api    # 看 uvicorn 啟動 log
```

### 9. 驗證

從 LAN 端:
```bash
curl -s -o /dev/null -w 'HTTP %{http_code}\n' https://bas.example.com/api/healthz
# 應 200(healthz 不需 auth)

curl -s -o /dev/null -w 'HTTP %{http_code}\n' https://bas.example.com/api/catalog
# 應 401(沒帶 auth)

curl -s -u admin:<password> https://bas.example.com/api/catalog | head -c 400
# 應回 catalog JSON

# 瀏覽器開 https://bas.example.com/ → 跑 dispatch → 驗 .10/.18 收得到 syslog
```

從白名單內的公網 IP:
```bash
# 同上,確認外部也能 200
```

從非白名單公網 IP(用手機行動網路測):
```bash
curl -s -o /dev/null -w 'HTTP %{http_code}\n' --max-time 5 https://bas.example.com/api/healthz
# 應 timeout(FortiGate drop)
```

---

## 日後更新

```bash
ssh lab@192.0.2.202
cd ~/CyberRange
git pull
docker compose up -d --build      # 滾動更新,downtime ~3 秒
```

---

## 回滾

最快速度(只下線 CyberRange,`<reverse-proxy>` 跟其他 vhost 不動):

```bash
cd ~/CyberRange
docker compose down
```

完全清除 vhost(連 SNI 也撤掉):

```bash
# 1. 從 `<reverse-proxy>` 移掉 bas vhost
cd ~/<reverse-proxy>
# 編 generate-conf.sh,VHOSTS 拿掉 "bas"
./generate-conf.sh
docker exec <reverse-proxy> rm /etc/nginx/conf.d/bas.example.com.conf
docker compose down && docker compose up -d

# 2. 撤 cert(可選)
sudo certbot delete --cert-name bas.example.com

# 3. Cloudflare DNS 撤 A record(手動)
# 4. FortiGate policy 拿掉 wan-to-bas-https + vip(若不再用)
```

---

## Phase 2 — TOTP 預留

`api/src/cyberrange_api/auth.py` 設計成 `AuthBackend` Protocol。之後加 TOTP:

1. 新增 `TotpBasicAuthBackend(BasicAuthBackend)`,Basic 通過後再要 6 位 OTP(`X-OTP` header 或 query)
2. `make_auth_dependency()` 看新 env(`CYBERRANGE_TOTP_SECRET_<user>`)決定要不要包一層
3. 既有 Basic 帳密不動,前端加 OTP 欄位

不需要動 routes / middleware。
