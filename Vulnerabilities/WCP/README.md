# Web Cache Poisoning
Web cache poisoning, Web önbelleklerinde değişiklik yaparak zararlı kod çalıştırılmasına olanak sağlayan bir saldırı türüdür.

# HTTP Header Mantığı
Header’lar, HTTP request ve response’larda veri taşır. Bu veriler, cache mekanizmalarının ve proxy’lerin nasıl davranacağını doğrudan etkiler.

## Cache-Control
Caching davranışını belirler.
Örnekler:
```
Cache-Control: no-cache
```
cache’lenmesin.

```
Cache-Control: public, max-age=3600
```
1 saat boyunca herkes için cache’lenebilir.

## Vary
Cache key oluşturulurken hangi header’ların da hesaba katılacağını söyler.

```
Vary: Accept-Encoding
```
gzip/deflate farkı varsa ayrı ayrı cache’le.

```
Vary: User-Agent
```

tarayıcıya göre farklı içerik üretiliyorsa cache ayrı tutulur.
