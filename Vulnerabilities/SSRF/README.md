# Server-Side Request Forgery
Bir web sunucusu, kullanıcı girdisine bağlı olarak uzak kaynakları getiriyorsa, saldırgan bu sunucuyu kendi belirlediği URL’lere istek göndermeye zorlayabilir. İlk bakışta bu çok kritik görünmese de, web uygulamasının yapılandırmasına bağlı olarak SSRF zafiyetleri çok ciddi sonuçlara yol açabilir. Ayrıca, eğer web uygulaması kullanıcıdan gelen URL şemasına veya protokolüne güveniyorsa, saldırgan URL şemasını manipüle ederek daha da istenmeyen davranışlara sebep olabilir. Örneğin, SSRF zafiyetlerinin istismarında yaygın olarak kullanılan URL şemalarından biri:
- gopher://: Belirtilen adrese rastgele byte’lar gönderebilir. Saldırgan bunu kullanarak keyfi HTTP POST istekleri gönderebilir veya SMTP sunucuları ya da veritabanları gibi diğer servislerle iletişim kurabilir.

# SSRF Keşfi
Aşağıdaki javascript kodu, imgUrl parametresinden aldığı kaynağı sunucu tarafında çekip kullanıcıya geri döndürür. Bu şekilde SSRF oluşur.
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