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

İlk sorgu gibi aşağıdaki sorguda tüm stunları döndürür, ardından LIMIT 1 ifadesi sadece bir veri satırı döndürmesini sağlar.
```sql
SELECT * FROM users LIMIT 1;
```

Son olarak where ifadesini kullnacağız, bu ifade belirli koşullara uyan verileri seçerek tam olarak ihtiyacınız olan veriyi seçmenizi sağlar.
```sql
SELECT * FROM users where username='admin'
```

Bu sadece kullanıcı adının admine eşit olduğu satırları döndürür.

LIKE ifadesini kullanmak, tam eşleşme olmayan ancak belirli karakterlerle başlayan, içeren veya biten verileri belirtmemizi sağlar. bunu yapmak için % kullanılır.
```sql
SELECT * FROM users where username LIKE 'a%';
```

## UNION 