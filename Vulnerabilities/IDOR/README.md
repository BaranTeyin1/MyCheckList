# IDOR
IDOR (Insecure Direct Object Reference), bir uygulamanın kullanıcıdan gelen girdiye dayalı olarak nesnelere doğrudan erişim sağlamasıyla ortaya çıkan bir güvenlik zafiyetidir. Bu durumda saldırganlar authorization mekanizmasını atlayarak sistemdeki kaynaklara doğrudan erişebilir. Bu zafiyet, authorization kontrolünün eksikliğinden kaynaklanır. 

Basitçe, uygulama kullanıcıdan aldığı ID, filename, record_number gibi değerleri doğrudan backend sorgularında kullanıyorsa ve erişim kontrolü yapılmıyorsa saldırganlar başka kullanıcıların verilerine ulaşabilir.

IDOR Örneği:
Bir web uygulamasının kullanıcılara profillerini görüntülemek için şu linki verdiğini düşünelim:
```
https://example.com/profile?user_id=123
```

Burada user_id=123 belirli bir kullanıcının profiline doğrudan referanstır. Eğer uygulama oturum açmış kullanıcının bu profile erişim hakkını düzgün kontrol etmezse, saldırgan user_id parametresini değiştirerek başka kullanıcıların profillerini görebilir.

REST API Üzerinden:
```
GET /api/orders/456
```

# Öngörülebilir ID’ler
Bazı uygulamalar tahmin edilebilir ID’ler üretir:
- Artan sayısal ID’ler: user_id=101, 102, 103
- UUID/GUID v1: Zaman damgası ve MAC adresi içerdiğinden öngörülebilir.
- UUID v4 ise rastgelelik sağladığı için brute force ile tahmini zordur.

# Wildcard Parameter
Bazı durumlarda ID yerine wildcard karakterleri (*, %, ., _) göndermek tüm kullanıcıların verisini döndürebilir:
```
GET /api/users/* HTTP/1.1
GET /api/users/% HTTP/1.1
GET /api/users/_ HTTP/1.1
GET /api/users/. HTTP/1.1
```

# Farklı Test Yöntemleri
- HTTP method değiştir: POST -> PUT
- Content type değiştir: XML -> JSON
- Sayısal değerleri array’e dönüştür: {"id":19} → {"id":[19]}
- Parameter Pollution kullan: user_id=hacker_id&user_id=victim_id

# IDOR Önleme Yöntemleri
- Backend her istekte ilgili kaynağa erişim hakkını doğrulamalı.
- Kullanıcıya doğrudan user_id=123 göstermek yerine, session’a bağlı token kullanılmalı.