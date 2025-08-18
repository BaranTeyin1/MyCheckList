# LDAP Injection
LDAP Injection, kullanıcıdan alınan parametrenin filtrelenmeden doğrudan LDAP sorgusuna eklenmesiyle ortaya çıkan bir güvenlik zafiyetidir. Saldırgan, sorguya kötü amaçlı ifadeler enjekte ederek hassas verilere erişebilir, komut çalıştırabilir veya uygulama içerisindeki yetkilerini yükseltebilir. Bu saldırı, mantık olarak SQL Injection zafiyetine oldukça benzer.

# LDAP Nedir
LDAP (Lightweight Directory Access Protocol), dizin servislerine erişmek ve yönetmek için kullanılan bir protokoldür. Kullanıcı kimlik doğrulaması için bir depo görevi görür ve SSO mekanizmasına olanak tanır. Yaygın olarak yetki yönetimi, kaynak yönetimi ve erişim kontrolü süreçlerinde kullanılır.

# LDAP Injection Nasıl Çalışır
LDAP sorguları genellikle kullanıcı girişlerinde, kimlik doğrulama mekanizmalarında veya arama fonksiyonlarında kullanılır. Örneğin, bir uygulama kullanıcıdan aldığı kullanıcı adı ve şifre parametrelerini doğrudan LDAP filtresine ekliyorsa, saldırgan bu parametreleri manipüle ederek sorgunun mantığını değiştirebilir.

## Authentication Bypass
Örnek olarak şu basit LDAP filtresini ele alalım:

```ldap
(&(uid=admin)(userPassword=12345))
```

Saldırgan, `kullanici_adi` alanına şu değerlerden birini enjekte edebilir:

```ldap
*)(|(uid=*))
admin)(&)
```

Sorgu şu hale dönüşür:

```ldap
(&(uid=*)(|(uid=*))(userPassword=12345))
```

Bu durumda filtre, tüm kullanıcıları döndürebilir ve kimlik doğrulama mekanizması bypass edilebilir.

## Privilege Escalation

LDAP Injection yalnızca kimlik doğrulama bypass’ı için kullanılmaz; aynı zamanda kullanıcıların erişim seviyelerini atlayarak yüksek ayrıcalıklı verilere ulaşmak için de kullanılabilir. Özellikle güvenlik seviyesi ile filtrelenen dizinlerde bu açık kritik hale gelir.

Örnek senaryo: Bir dizin servisi, belgeleri şu filtre ile getiriyor:

```ldap
(&(department=Finance)(access_level=employee))
```

Bu filtre, normalde yalnızca “employee” seviyesindeki kullanıcıların görebileceği finans belgelerini döndürecektir.

Saldırgan, kullanıcı girişine şu değeri enjekte ederse:

```ldap
Finance)(access_level=*))(&(department=*
```

Filtre şu hale gelir:

```ldap
(&(department=Finance)(access_level=*))
(&(department=Finance)(access_level=employee))
```

LDAP motoru yalnızca ilk filtreyi işler:

```ldap
(&(department=Finance)(access_level=*))
```

Böylece saldırgan, normalde yalnızca yüksek yetkiye sahip kullanıcıların görebileceği tüm belgeleri listeleyebilir. Bu yöntemle, düşük yetkili bir kullanıcı bile “confidential” veya “management-only” belgeleri görüntüleyebilir.