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
Header’lar, HTTP request ve response’larda veri taşır. Bu veriler, cache mekanizmalarının ve proxy'lerin nasıl davranacağını doğrudan etkiler.

## Cache-Control
Caching davranışını belirler.
Örnekler:
```
Cache-Control: no-cache
```
cache'lenmesin.

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

# Cache Key
Cache key genelde şu bileşenlerden oluşur:

- Scheme: http vs.
- Host: example.com
- Path: /index.php
- Query string: ?id=123
- Vary header'ları: Accept-Encoding, User-Agent gibi belirlenen header’lar

Cache mantığına göre bu key ile saklanır. Eğer başka bir kullanıcı aynı request’i yaparsa cache’den gelir.

# Unkeyed Input
Cache key, sadece belirli alanları hesaba katar. Ama  response içeriği, key dışında kalan şeylerden etkilenebilir. bunlara Unkeyed Input denir.

Örnek Unkeyed Input Senaryoları:
### Header’lar
```
X-Forwarded-For 
```
uygulama response’u buna göre kişiselleştirir, ama cache key’e dahil edilmezse → cache zehirlenir.

```
User-Agent 
```
response farklı ama cache key’e dahil edilmemiş.

### Query parametreleri
Bazı parametreler response’u etkiler ama cache key normalleştirmede göz ardı edilmiştir.

Örn: ?debug=true.

### Cookies
Response cookie’ye göre değişir ama cache bunu ayırt etmez.

Eğer response’u etkileyen bir input cache key’e dahil edilmemişse, saldırgan bu input’u kullanarak cache’i zehirleyebilir. Saldırgan unkeyed input ile zararlı response üretir.mCache bu response’u yanlışlıkla tüm kullanıcılar için geçerliymiş gibi saklar. Normal kullanıcı cache’den zehirli response’u alır.