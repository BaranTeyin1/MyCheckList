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
