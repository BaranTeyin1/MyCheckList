#  Recon Pipeline (Subdomain ➝ Endpoint ➝ Vulnerability Scanning)

## Subdomain Enumeration

### Pasif Yöntemler

```bash
# Subfinder
subfinder -d example.com -all -silent > subfinder.txt

# Assetfinder
assetfinder --subs-only example.com > assetfinder.txt

# Findomain
findomain -t example.com -q > findomain.txt

# Puredns (bruteforce)
puredns bruteforce brute_subs.txt example.com -r resolvers.txt > puredns
```

# Subdomain’leri Birleştir ve Temizle
cat subfinder.txt assetfinder.txt puredns.txt findomain.txt | sort -u > all_subdomains.txt


## Live Host Identification

```bash
# HTTP servislerini dinleyen subdomain'leri tespit et
httpx -l all_subdomains.txt -timeout 10 -threads 100 -o live_subdomains.txt
```

## URL / Endpoint Discovery

### Arşiv ve Pasif Kaynaklar
```bash
# GAU (Wayback + Common Crawl)
cat live_subdomains.txt | gau --threads 50 > urls_gau.txt

# Waybackurls
cat live_subdomains.txt | waybackurls > urls_wayback.txt
```

### JS Tabanlı / Aktif Tarayıcılar

```bash
# Waymore (JS parsing + URL extraction)
waymore -i example.com -mode U -oU waymore.txt

# Katana (modern JS destekli crawler)
katana -list live_subdomains.txt -depth 10 -jc -silent -o urls_katana.txt
```
### Parametre Keşfi

```bash
# Paramspider (light param finder)
paramspider -l live_subdomains.txt -o paramspider.txt

# Arjun (API param brute)
arjun -i live_subdomains.txt -t 50 -oT arjun.txt
```
#### Tüm URL Kaynaklarını Birleştir

```bash
cat urls_gau.txt urls_wayback.txt waymore.txt urls_katana.txt paramspider.txt arjun.txt | sort -u > all_urls.txt
```

## URL Temizliği & Canlı URL'ler

```bash
# Statik Dosyaları Filtrele
egrep -v '\.(css|js|png|jpg|jpeg|gif|svg|woff|woff2|ttf|eot|ico|pdf|txt|docx?|xlsx?|pptx?|zip|tar|gz|rar)$' all_urls.txt | sort -u > clean_urls.txt

# Canlı URL Tespiti
httpx -l clean_urls.txt -threads 150 -o live_urls.txt
```

## Zafiyet Taraması (Nuclei)

```bash 
# Parametreli URL'leri Ayıkla
grep -a '=' clean_urls.txt > parameterized_urls.txt

# Nuclei ile Tarama
nuclei -l parameterized_urls.txt \
  -tags 'xss,sqli,ssrf,redirect,lfi,rce,idor' \
  -severity low,medium,high,critical \
  -o nuclei_results.txt
```
