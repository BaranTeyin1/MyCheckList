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

### Headers
Her satır Key: Value formatındadır.
Önemli olanlar:

**Host**:
```
Host: example.com
```

HTTP/1.1’de zorunludur. Çünkü bir IP üzerinde birden fazla sanal host olabilir.

**Content-Length**:
```
Content-Length: 42
```

Body’nin kaç byte olduğunu belirtir.

**Transfer-Encoding**:
```
Transfer-Encoding: chunked
```

Body’nin parça parça gönderileceğini belirtir. Eğer bu header varsa Content-Length yok sayılır.

**Connection**:
```
Connection: keep-alive
```

Persistent connection kontrolü. HTTP/1.1’de varsayılan keep-alive’dır.

### Body
GET’lerde genelde boş olur. POST/PUT gibi methodlarda data taşır.

Örnek POST request:
```
POST /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 27
Connection: keep-alive

username=admin&pass=123
```
