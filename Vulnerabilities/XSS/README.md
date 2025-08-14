# XSS
XSS açıkları genellikle saldırganın kurban kullanıcı gibi davranmasına, kullanıcının yapabileceği tüm işlemleri gerçekleştirmesine ve kullanıcıya ait tüm verilere erişmesine olanak tanır. Eğer kurban kullanıcı uygulama içinde ayrıcalıklı yetkilere sahipse, saldırgan uygulamanın tüm işlevselliği ve verileri üzerinde tam kontrol sağlayabilir. XSS, güvenlik açığı bulunan bir web sitesinin, kullanıcıya kötü amaçlı JavaScript kodu döndürmesini sağlamakla çalışır. Bu kötü amaçlı kod kurbanın tarayıcısında çalıştığında, saldırgan kurbanın uygulama ile olan etkileşimini tamamen ele geçirebilir.

# XSS Saldırı Türleri
Üç ana XSS türü vardır:
- Reflected XSS – Kötü amaçlı script mevcut HTTP isteğinden gelir.
- Stored XSS – Kötü amaçlı script web sitesinin veritabanından gelir.
- DOM-based XSS – Açık, sunucu tarafında değil istemci tarafındaki JavaScript kodunda bulunur.

## Reflected XSS
Reflected XSS açıkları, girdiğimiz verinin arka uç sunucuya ulaşması ve herhangi bir filtreleme veya sanitizasyon yapılmadan bize geri döndürülmesiyle oluşur. Çoğu durumda, tüm girdimiz bize geri dönebilir. Bu, örneğin hata mesajlarında veya onay mesajlarında görülebilir. Böyle durumlarda, XSS payload’larımızı deneyerek çalışıp çalışmadığını görebiliriz. Ancak bu mesajlar genellikle geçici olduğundan, sayfadan ayrıldığımızda tekrar çalışmazlar. Bu nedenle Non-Persistent olarak sınıflandırılırlar. Reflected XSS, en basit XSS türüdür. Uygulama, HTTP isteğinde aldığı veriyi doğrudan ve güvenli olmayan şekilde yanıta dahil ettiğinde ortaya çıkar.

Örnek:
```html
https://insecure-website.com/status?message=All+is+well
<p>Status: All is well.</p>
```

Saldırgan, URL’yi şu şekilde değiştirebilir:
```html
https://insecure-website.com/status?message=<script>/* Bad stuff here... */</script>
```

Kurban bu linke tıkladığında, script tarayıcıda kurbanın oturumu bağlamında çalışır.