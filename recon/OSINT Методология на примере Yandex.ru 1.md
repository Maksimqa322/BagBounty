

## Получение поддоменов

### crt.sh (public CT logs)

```bash
curl -s "https://crt.sh?q=yandex.ru&output=json" \
  | jq -r '.[].name_value' \
  | grep -Po '(\w+\.)+yandex\.ru' \
  | sort -u > subdomains.yandex.crtsh.txt
```

### Chaos ProjectDiscovery

```bash
chaos -d yandex.ru -key "<API_KEY>" | sort -u > subdomains.yandex.chaos.txt
chaos -d yandex.ru -key "<API_KEY>" | alterx -enrich | sort -u > subdomains.yandex.chaos.enriched.txt
```

### alterx + dnsx (брут DNS)

```bash
echo yandex.ru \
  | alterx -pp word=/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  | dnsx | sort -u > subdomains.yandex.alterx.txt
```

### Amass (passive)

```bash
amass enum -passive -d yandex.ru \
  | grep -oE '([a-zA-Z0-9_-]+\.)+yandex\.ru' \
  | sort -u > subdomains.yandex.amass.txt
```

### GitHub (поиск упоминаний)

```bash
github-subdomains -d yandex.ru -t "<GITHUB_TOKEN>" > github.yandex.txt
```

### Wayback Machine

```bash
curl -s "http://web.archive.org/cdx/search/cdx?url=*.yandex.ru/*&output=text&fl=original&collapse=urlkey" \
  | sort \
  | sed -e 's_https*://__' -e "s/\/.*//" -e 's/:.*//' -e 's/^www\\.//' \
  | sort -u > wayback.yandex.txt
```

### VirusTotal

```bash
curl -s "https://www.virustotal.com/vtapi/v2/domain/report?apikey=<VT_API_KEY>&domain=www.yandex.ru" \
  | jq -r '.domain_siblings[]' \
  | sort -u > virustotal.yandex.txt
```

---

## Поиск IP-адресов

### VirusTotal (IP address extraction)

```bash
curl -s "https://www.virustotal.com/vtapi/v2/domain/report?apikey=<VT_API_KEY>&domain=www.yandex.ru" \
  | jq -r '.. | .ip_address? // empty' \
  | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' \
  | sort -u | httpx-toolkit -sc
```

### AlienVault OTX

```bash
curl -s "https://otx.alienvault.com/api/v1/indicators/hostname/www.yandex.ru/url_list?limit=500&page=1" \
  | jq -r '.url_list[]?.result?.urlworker?.ip // empty' \
  | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' \
  | sort -u | httpx-toolkit -sc
```

### urlscan.io

```bash
curl -s "https://urlscan.io/api/v1/search/?q=domain:www.yandex.ru&size=10000" \
  | jq -r '.results[]?.page?.ip // empty' \
  | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' \
  | sort -u | httpx-toolkit -sc
```

### Shodan (SSL и поиск IP)

```bash
shosubgo -d yandex.ru -s "<SHODAN_API_KEY>" | httpx-toolkit -sc -td -title

shodan search Ssl.cert.subject.CN:www.yandex.ru 200 --fields ip_str \
  | httpx-toolkit -sc -title -server -td
```

---

## FUZZ и неизвестные поддомены

```bash
ffuf -u "https://FUZZ.yandex.ru" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  -mc 200,301,302 >> ffuf.yandex.txt
```

---

## Amass intel (пассивное сбор инфры)

```bash
amass intel -active -cidr 159.69.129.82/32
amass intel -active -asn 136629
```

---

## Сканирование, скриншоты, nuclei

### Скриншоты доступных хостов

```bash
cat yandex.ru.txt | aquatone
```

### nuclei (массовый скан)

```bash
cat yandex.ru.txt | nuclei -bs 50 -c 30
```

---

## Whois и MX

- [https://mxtoolbox.com](https://mxtoolbox.com/) — искать email
    
- [https://tool.whoisxmlapi.com/](https://tool.whoisxmlapi.com/) — по email получать домены
    

---

## Поиск админки и портов

```bash
chaos -d yandex.ru | httpx-toolkit -ports 80,443,8080,8000,8888 -threads 200
```

---
