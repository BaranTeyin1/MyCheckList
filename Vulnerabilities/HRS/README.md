#  HTTP Request Smuggling
HTTP Request Smuggling client ile backend sunucu arasındaki HTTP request parsing farklarını istismar ederek, tek bir HTTP request içerisine smuggled ikinci bir request enjekte etme saldırı tekniğidir. Proxy ile backend, HTTP header’larını farklı yorumladığında ortaya çıkar (özellikle Content-Length ve Transfer-Encoding uyumsuzlukları).

## HTTP/1.1 Request Yapısı
Bir HTTP isteği üç ana bölümden oluşur:

### Request Line
Örnek:
```
GET /products?id=5 HTTP/1.1
```

- GET → HTTP Method
- /products?id=5 → Path + Query
- HTTP/1.1 → Protokol versiyonu