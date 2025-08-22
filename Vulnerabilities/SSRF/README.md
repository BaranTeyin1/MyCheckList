# Server-Side Request Forgery
Bir web sunucusu, kullanıcı girdisine bağlı olarak uzak kaynakları getiriyorsa, saldırgan bu sunucuyu kendi belirlediği URL’lere istek göndermeye zorlayabilir. İlk bakışta bu çok kritik görünmese de, web uygulamasının yapılandırmasına bağlı olarak SSRF zafiyetleri çok ciddi sonuçlara yol açabilir. Ayrıca, eğer web uygulaması kullanıcıdan gelen URL şemasına veya protokolüne güveniyorsa, saldırgan URL şemasını manipüle ederek daha da istenmeyen davranışlara sebep olabilir. Örneğin, SSRF zafiyetlerinin istismarında yaygın olarak kullanılan URL şemalarından biri:
- gopher://: Belirtilen adrese rastgele byte’lar gönderebilir. Saldırgan bunu kullanarak keyfi HTTP POST istekleri gönderebilir veya SMTP sunucuları ya da veritabanları gibi diğer servislerle iletişim kurabilir.

# SSRF Keşfi (Minimal PHP Örneği)
Aşağıdaki küçük python kodu, url parametresinden aldığı kaynağı sunucu tarafında çekip kullanıcıya geri döndürür. Bu şekilde SSRF oluşur.
```Py
from flask import Flask, request
from urllib.parse import urlparse
import http.client

app = Flask(__name__)

@app.route('/pfp')
def pfp():
    url = urlparse(request.args.get('url'))
    conn = http.client.HTTPConnection(url.hostname, url.port)
    conn.request('GET', url.path)
    response = conn.getresponse()
    user.updateProfileImage(response.read())
    return response.read()

if __name__ == '__main__':
    app.run(port=3000)
```