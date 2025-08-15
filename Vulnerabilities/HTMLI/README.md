# HTML Injection Nedir?
HTML Injection, bir web uygulamasının kullanıcıdan aldığı veriyi HTML çıktısına filtrelemeden veya encode etmeden yerleştirmesi sonucu oluşan güvenlik açığıdır. Bu açıkta saldırgan HTML etiketleri enjekte ederek sayfanın DOM yapısını manipüle eder.

Örnek Senaryo:
```php
<!-- Kullanıcı profil sayfası -->
<p>Merhaba, <?php echo $_GET['name']; ?>!</p>
```

Kullanıcı şu URL’i açarsa:
```
https://example.com/profile.php?name=<h1>HACKED</h1>
```

Sonuçta:

```html
<p>Merhaba, <h1>HACKED</h1>!</p>
```

Sayfanın HTML yapısı bozulur ve görünüm değişir.

## XSS ile Benzerlik ve Farklar
Benzerlikler:
- İkisi de istemci taraflı çalışır.
- Kullanıcıdan gelen input’un encode edilmemesiyle ortaya çıkar.
- DOM manipülasyonu yapılabilir.

Farklar:
| Özellik               | HTML Injection                                                      | XSS                                                                              |
| --------------------- | ------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| Çalışma Garantisi | Sadece HTML/DOM manipülasyonu; JavaScript çalıştırma garantisi yok. | Doğrudan JavaScript çalıştırılabilir (alert, cookie çalma, keylogger vb.).       |
| Etki Alanı        | Görsel değişiklik, phishing form ekleme, sahte içerik               | JavaScript ile çerez, localStorage, token çalma, vb. |                                                  |                                                 |

Kritik Not:
HTML Injection bazı durumlarda XSS’e dönüşebilir. Örneğin:

- `<img src=x onerror=alert(1)>` gibi HTML elementleri üzerinden JS çalıştırmak mümkünse, bu XSS olur.
- Ama sadece `<h1>`, `<p>`, `<div>` gibi pasif etiketler enjekte edilebiliyorsa, bu saf HTML Injection’dır.

Tamam, bunu da teknik detaylarıyla ve context/payload farklılıklarıyla açıklayayım.

## HTML Injection Nasıl Oluşur
HTML Injection, kullanıcı girdisinin HTML çıktısına eklenmeden önce HTML context’ine uygun şekilde escape edilmemesi sonucu oluşur.

Buna en sık neden olan riskli kullanım şekilleri:
- `innerHTML` → Tarayıcı, string’i doğrudan HTML olarak parse eder.
- `document.write()` → HTML’e direkt enjekte eder.
- String concatenation (ör. `"<div>" + userInput + "</div>"`) → HTML parser’a ham veri gönderir.

## HTML Injection Nasıl Önlenir?
HTML Injection açıklarını engellemek için şu önlemler uygulanmalıdır:

### Output Encoding
Kullanıcıdan gelen veriyi HTML context’e koymadan önce HTML entity’lerine çevirin.
Örnek PHP’de:
```php
<?php echo htmlspecialchars($userInput, ENT_QUOTES, 'UTF-8'); ?>
```

JavaScript’te:
```javascript
element.textContent = userInput; // innerHTML yerine
```

### Güvenli DOM API’leri Kullanma
* `innerHTML` yerine `textContent` veya `innerText` kullanın.
* HTML attribute eklerken `setAttribute()` ile değerleri escape edin.

### HTML Template Engine Kullanımı
Modern template engine’ler (Twig, Mustache, Handlebars) otomatik olarak escape işlemi yapar.

### Content Security Policy (CSP)
HTML Injection doğrudan engellemez ama XSS’e dönüşmesini zorlaştırır.
Örneğin:
```http
Content-Security-Policy: default-src 'self'; script-src 'self';
```
