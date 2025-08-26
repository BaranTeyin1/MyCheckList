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

# Proxy / Reverse Proxy / Load Balancer
- Reverse Proxy: Backend’i korur, caching yapar, SSL terminate eder. (Nginx, Cloudflare)
- Load Balancer: Gelen request’leri birden fazla backend arasında dağıtır.

Bu katmanların hepsi HTTP header’ları okur ve tekrar yazar. Ama hepsi RFC’yi farklı yorumlayabilir.

# Header Yorumlama Farklılıkları
**Content-Length**:
Body’nin kaç byte olduğunu belirtir. Tek başına kullanıldığında problem çıkmaz ama Transfer-Encoding ile çakışırsa sorun başlar.

**Transfer-Encoding: chunked**:
Body parça parça gönderilir. Eğer bu varsa, HTTP standardına göre Content-Length yok sayılmalıdır. Ama bazı proxy’ler yine de Content-Length’e bakar parsing farkı doğar.

**Connection**:
keep-alive → aynı TCP connection üzerinde yeni request gelebilir. close → connection kapanır. Proxy “keep-alive” derken backend “close” diyorsa, request zinciri kopabilir veya farklı parse edilir.

## Header Çakışması Örneği
```
POST / HTTP/1.1
Host: victim.com
Content-Length: 12
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: victim.com
```

Proxy (Content-Length’i baz alıyor):
- Body = 12 byte → request burada bitti sanıyor.
- "GET /admin …" kısmını yeni request olarak backend’e yolluyor.

Backend (Transfer-Encoding’i baz alıyor):
- Chunked parsing başlatıyor.
- 0 gördüğü anda "body bitti" diyor.
- Sonraki kısım (GET /admin ...) aynı TCP connection içinde geliyor ve geçerli yeni request oluyor.

Proxy ve backend request sınırında anlaşamıyor HTTP Request Smuggling gerçekleşiyor.

## Smuggling’in Doğduğu Yer
Proxy ve backend’in farklı HTTP standardı yorumlaması. Birinin Content-Length’e, diğerinin Transfer-Encoding’e güvenmesi.