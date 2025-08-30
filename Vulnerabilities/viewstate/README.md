# ViewState Nedir?
ASP.NET sayfalarının ve kontrollerin durum bilgisini saklayan yapıdır. Sunucu, istemci, sunucu arasında _VIEWSTATE hidden input alanı ile taşınır. Serialize edilmiş  veri içerir. ASP.NET tarafından default olarak LosFormatter ile serileştirilir, ObjectStateFormatter ile deserialize edilir.

# Güvenlik Mekanizmaları
## MAC (Message Authentication Code)
ViewState’in değiştirilip değiştirilmediğini doğrular. EnableViewStateMac=true ise devrede olur. MAC kapalıysa saldırgan ViewState’i manipüle edebilir.

## EventValidation
Sunucuya gönderilen değerlerin beklenen/güvenilir değerlerden olup olmadığını kontrol eder. Kapatılırsa key injection veya postback manipulation gibi saldırılar yapılabilir.

# ViewState Deserialization
Eğer ViewState şifrelenmemiş ve machineKey biliniyorsa / zayıfsa, saldırgan zararlı ViewState payload’ı hazırlayabilir. Bu payload deserialize edilirken çalıştırılır.

Saldırgan gadget chain kullanarak zararlı ViewState üretir. Bu payload deserialize edilirken zararlı kod çalıştırılır.
Örnek:
```
ysoserial.exe -f LosFormatter -g TypeConfuseDelegate -o base64 -c "calc.exe"
```

```
POST /vulnerable.aspx HTTP/1.1
Host: vulnerable.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 

__VIEWSTATE=/wEPDwUJODg3NzQ2NjQ5ZGQ... (ysoserial.net ile hazırlanmış zararlı payload)
```

Bu base64 payload, _VIEWSTATE input alanına enjekte edilir.

# ViewState Güvenliği
MAC’i Açık Tut
```
<%@ Page EnableViewStateMac="true" %>
```

ViewState’i Şifrele
```
<%@ Page ViewStateEncryptionMode="Always" %>
```


