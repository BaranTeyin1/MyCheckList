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


