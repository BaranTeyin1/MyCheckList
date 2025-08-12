# SQL Injection
SQL Injection, kullanıcıdan alınan verinin doğrudan SQL sorgusuna eklenmesi ve yeterli filtreleme/sanitizasyon yapılmaması sonucunda ortaya çıkan bir güvenlik zafiyetidir.
Bu zafiyetin istismarı ile saldırgan:
- Veritabanındaki tüm verileri okuyabilir,
- Veri ekleyebilir/güncelleyebilir/silebilir,
- Yetkileri aşarak hassas bilgilere erişebilir,
- Bazı durumlarda işletim sistemi seviyesinde komut çalıştırabilir.

# SQL Nedir
SQL (Structured Query Language), ilişkisel veritabanlarında depolanan verileri yönetmek ve sorgulamak için kullanılan standart bir dildir; temel olarak verileri okuma (SELECT), ekleme (INSERT), güncelleme (UPDATE) ve silme (DELETE) işlemlerini yapmanı, ayrıca tablolar ve veritabanı yapısını oluşturma (CREATE), değiştirme (ALTER) ve silme (DROP) gibi işlemlerle veritabanını düzenlemeni sağlar. SQL bilmek, SQL Injection (SQLi) gibi zafiyetleri anlamanın temelidir çünkü bu saldırılar, veritabanıyla etkileşim şeklimizi manipüle ederek çalışır.

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
Bir tablo stünlardan ve satırlardan oluşur.