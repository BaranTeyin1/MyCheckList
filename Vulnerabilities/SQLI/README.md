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