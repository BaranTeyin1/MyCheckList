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

---

Kritik Not:
HTML Injection bazı durumlarda XSS’e dönüşebilir. Örneğin:

* `<img src=x onerror=alert(1)>` gibi HTML elementleri üzerinden JS çalıştırmak mümkünse, bu XSS olur.
* Ama sadece `<h1>`, `<p>`, `<div>` gibi pasif etiketler enjekte edilebiliyorsa, bu saf HTML Injection’dır.

