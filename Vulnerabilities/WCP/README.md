# Web Cache Poisoning
Web cache poisoning, Web önbelleklerinde değişiklik yaparak zararlı kod çalıştırılmasına olanak sağlayan bir saldırı türüdür.

# Caching Mekanizmaları
Caching’in temel amacı aynı cevabı tekrar üretmek yerine saklamak ve performans/artırılmış hız sağlamaktır.

## Browser Cache
-  Kullanıcının kendi tarayıcısında.
- Cache-Control, ETag, Last-Modified gibi header’larla kontrol edilir.

## Reverse Proxy Cache
- Kullanıcı ile web server arasında duran cache.
- En kritik nokta: Buradaki cache genellikle shared  bir kullanıcı için zehirlenen response başka kullanıcılara da sunulur.
- Web Cache Poisoning saldırılarının asıl hedefi budur.

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
