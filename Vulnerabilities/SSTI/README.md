# SSTI Nedir
Server-Side Template Injection , web uygulamalarında kullanılan template engine’lerin kullanıcı girdilerini doğru şekilde filtrelemeden şablona dahil etmesi sonucunda oluşan bir güvenlik zafiyetidir.

Şablon motorları (ör. Jinja2, Twig, Freemarker) dinamik içerik oluşturmak için kullanılır. Amaç, backend verilerini HTML veya başka formatlara kolayca gömmektir. Eğer geliştirici, kullanıcıdan aldığı girdiyi doğrudan şablon içine koyarsa, saldırgan template engine’in kendi scripting yeteneklerini kötüye kullanarak:

- Bilgi sızdırma (ör. sistem path, config değerleri)
- Uzaktan kod çalıştırma (RCE)

gibi saldırılar gerçekleştirebilir.

Örneğin:
```py
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/")
def index():
    user = request.args.get("name", "Guest")
    return render_template_string("Hello " + user)
```

Burada ?name={{7*7}} şeklinde bir istek gönderildiğinde, çıktı Hello 49 olacaktır. Bu da SSTI’nin en basit PoC’lerinden biridir.