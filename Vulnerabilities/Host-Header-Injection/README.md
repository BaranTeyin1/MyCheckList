# Host Header Nedir
Host header istemcinin erişmek istediği domaini belirtir. Örneğin bir kullanıcı http://example.com/login URL'ine gitmek istediğinde aşağıdaki HTTP isteğini gönderir:

```http
GET /login HTTP/1.1
Host: example.com
```

Host header'ın temel amacı istemcinin hangi backend bileşenine erişmek istediğini söylemektir. Geçmişte buna ihtiyaç duymuyorduk çünkü bir IP adresi sadece bir domain yayınlıyordu ancak günümüzde bulut tabanlı çözümler gibi şeylerin yaygınlaşması ile bir IP adresinden birden fazla uygulamanın yayınlanması yaygınlaştı.

# Host Header Injection Nedir
Host Header Injection saldırsı Host header'ının güvensiz işlenmesinden kaynaklanır. Eğer sunucu bu değere koşulsuz güvenir ve filtreleme yapmazsa payload enjekte edilebilir. Host header içine doğrudan payload enjekte edilerek yapılan saldırılara Host header injection denir. Web uygulamaları genellikle hangi domain üzerinde çalıştığını bilmez. Bu bilgi kurulum sırasında yapılandırma dosyasına manuel olarak girilmemişse, uygulama bazen ihtiyaç duyduğu domain bilgisi için doğrudan Host header değerini kullanır. Örneğin:

```php
<a href="https://$_SERVER['HOST']/support">Contact support</a>
```

Eğer bu giriş uygun şekilde doğrulanmaz veya kaçış yapılmazsa, bir çok zafiyet türürnün istismarı mümkün hale gelir.

# Host Header Injection Zafiyetleri Nasıl Ortaya Çıkar
Bir saldırgan, örneğin Burp Proxy gibi araçlar kullanarak bu header’ı kolayca değiştirebilir.

Ayrıca bazı durumlarda Host header doğrudan güvende olsa bile, sunucunun yapılandırmasına bağlı olarak diğer alternatif başlıklar kullanılarak bu değer geçersiz kılınabilir.

# HTTP Host Header Zafiyetlerini Tespit Etme ve İstismar Etme
Temel hedef şudur:
İsteğinde Host header’ı değiştirip hedef uygulamaya hâlâ erişebiliyor musun? Eğer evet ise, bu header’ı kullanarak uygulamayı daha derinlemesine analiz edip sunucunun nasıl davrandığını gözlemleyebilirsin.

## Rastgele Host Header Değeri Gönderme
Host header injection zafiyetlerini araştırırken ilk adım:
Tanımlı olmayan bir alan adı gönderip uygulamanın buna nasıl yanıt verdiğini test etmektir.

Bazen "Invalid Host header" yerine, başka bir güvenlik önlemi nedeniyle isteğin engellenebilir.
Örneğin, bazı uygulamalar Host header’ın, TLS el sıkışması sırasında iletilen SNI (Server Name Indication) ile uyumlu olup olmadığını kontrol eder. Bu, sitenin tamamen güvenli olduğu anlamına gelmez. Örneğin:

- Port manipülasyonu: Bazı algoritmalar port kısmını göz ardı eder ve sadece domain’i doğrular. Eğer numeric olmayan bir port kullanırsan, domain değişmeden kalır ama payload’ını porta enjekte edebilirsin.

## Çelişkili HTTP İstekleri Gönderme
Çoğu zaman Host header'ı doğrulayan kod ile işleyen kod farklı sunucularda bulunur. Bu durum, aynı isteğin farklı sistemler tarafından farklı yorumlanmasına neden olabilir.

1. Duplicate Host Header (Çift Host Header)
```http
GET /example HTTP/1.1  
Host: vulnerable-website.com  
Host: bad-stuff-here
```

2. Absolute URL Kullanımı

Normalde HTTP istekleri şu şekildedir:
```http
GET /path HTTP/1.1  
Host: example.com
```

Ancak, bazı sunucular tam URL içeren istekleri de işler:
```http
GET https://vulnerable-website.com/ HTTP/1.1  
Host: bad-stuff-here
```

### Diğer Teknikler

Yukarıdakiler sadece birkaç örnektir. Örneğin:

    HTTP request smuggling tekniklerinin çoğu, Host header saldırılarına uyarlanabilir.
    Bununla ilgili daha fazla detayı request smuggling konusuna özel bölümde ele alacağız.

# Host Override Header’ları Enjekte Etme
Daha önce de bahsettiğimiz gibi, birçok web sitesi bir tür ara sistem (örneğin load balancer veya reverse proxy) üzerinden erişilir.
Bu mimaride, arka uç sunucunun aldığı Host header değeri genellikle bu ara sistemin domain adını içerir. Ancak bu bilgi, uygulama işlevi için çoğu zaman anlamsızdır.
Bu sorunu çözmek için, front-end sistemler sıklıkla X-Forwarded-Host başlığını enjekte eder ve bu başlıkta istemcinin orijinal Host değeri yer alır. Dolayısıyla, bazı durumlarda Host header üzerindeki doğrulamaları aşarak zararlı girdini X-Forwarded-Host ile enjekte edebilirsin:

```http
GET /example HTTP/1.1
Host: vulnerable-website.com
X-Forwarded-Host: bad-stuff-here
```

Aynı amacı taşıyan diğer başlıkları da deneyebilirsiniz:
- X-Host
- X-Forwarded-Server
- X-HTTP-Host-Override
- Forwarded

# HTTP Host Header Zafiyetleri Nasıl İstismar Edilir?
## Host Header Üzerinden Web Cache Poisoning
Host header ile ilgili zafiyet araştırmaları sırasında bazen görünüşte zafiyetli ama doğrudan istismar edilemeyen davranışlar olabilir.
Örneğin, host header değeri response içinde encode edilmeden yansıtılıyor olabilir. Bu tip yansıtılmış client-side zafiyetler (örneğin XSS), Host header yoluyla tetiklenemez. Çünkü bir saldırganın mağdurun tarayıcısını farklı bir Host header göndermeye zorlaması mümkün değildir. Ancak eğer hedefte web cache kullanılıyorsa, bu önemsiz gibi görünen yansıyan zafiyeti, tehlikeli bir stored zafiyete çevirebilirsin.
Yani: cache’i zehirleyerek, diğer kullanıcılara kötü niyetli response’ların sunulmasını sağlayabilirsin. Örneğin:

```http
GET / HTTP/1.1
Host: "><img src=x onerror=alert(document.cookie)>
```

# Klasik Sunucu Tarafı Zafiyetlerin İstismarı
Her HTTP header, klasik sunucu tarafı zafiyetlerin istismarı için potansiyel bir saldırı vektörüdür — Host header da bir istisna değildir.
Bu nedenle, SQL injection gibi klasik zafiyetlere yönelik test teknikleri Host header üzerinden de denenebilir.

# Yönlendirme Tabanlı SSRF
Klasik SSRF zafiyetleri genellikle XXE veya kullanıcı kontrollü girdiden türetilen URL’lere gönderilen HTTP istekleri üzerinden gerçekleşir.
Routing-based SSRF ise, çoğunlukla bulut mimarilerinde yaygın olan ara bileşenleri (reverse proxy, load balancer vs.) istismar etmeye dayanır. Bu bileşenler genellikle gelen istekleri alır ve uygun back-end sunucuya yönlendirir.

# HTTP Host Header Saldırıları Nasıl Önlenir?

HTTP Host header saldırılarını önlemek için en basit ve etkili yaklaşım, sunucu tarafı kodlarda Host header kullanımından tamamen kaçınmaktır. Host header’ı kullanmanız gerekiyorsa mutlaka whitelist ile doğrulayın. Sadece izin verilen domain'ler üzerinden gelen istekleri kabul edin. Örneğin Django'da bu iş için ALLOWED_HOSTS yapılandırması kullanılır. Özellikle X-Forwarded-Host gibi alternatif header’ların varsayılan olarak aktif olabileceğini unutmayın. Bunların sunucu veya framework seviyesinde desteklenip desteklenmediğini kontrol edin ve gerekiyorsa devre dışı bırakın.

Referanslar:
- https://portswigger.net/web-security/host-header
- https://www.youtube.com/watch?v=I6LZ6e5O-Ao
