# Privilege Escalation
Privilege Escalation, bir kullanıcının normalde izin verilenden daha fazla kaynağa veya işlevselliğe erişim elde etmesi durumunda ortaya çıkar 

- Dikey Privilege Escalation: Daha yetkili hesaplara tanınan kaynaklara erişmek.
- Yatay Privilege Escalation: Benzer yapılandırılmış bir hesaba tanınan kaynaklara erişmek.

# Nasıl Test Edilir
Kullanıcının veritabanına bilgi oluşturabildiği, bilgi alabildiği veya bilgi silebildiği her noktada bu işlevler kaydedilmelidir. Bu işlevlere başka bir kullanıcı gibi erişmeye çalışarak, kullanıcının rolü/yetkisi ile erişmemesi gereken işlevlere erişip erişemediğini kontrol etmelidir.

## Kullanıcı Grubu Manipülasyonu
Örnek: Aşağıdaki HTTP isteği, grp001 grubuna ait bir kullanıcının #0001 numaralı siparişe erişmesine izin verir:
```
POST /user/viewOrder.jsp HTTP/1.1
Host: www.example.com

groupID=grp001&orderID=0001
```

groupID ve orderID değerlerini değiştirerek yetkisiz bir kullanıcının ayrıcalıklı verilere erişip erişemediği doğrulanmalıdır.

## IP Adresi Manipülasyonu
Bazı siteler IP’ye göre giriş denemelerini sınırlayabilir. X-Forwarded-For başlığındaki IP değiştirilebilir:
```
X-Forwarded-For: 8.1.1.1
```

Eğer uygulama bu değere güveniyorsa, IP tabanlı kısıtlamalar atlatılabilir.

# URL Traversal
Bazı sayfalarda yetkilendirme kontrolü atlanabilir. Örn:
```
/../.././userInfo.html
```

Eğer kontrol yalnızca startswith(), endswith(), contains(), indexOf() gibi yöntemlerle yapılmışsa, URL encode yöntemleriyle atlatılabilir.




