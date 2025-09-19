# Race Condition
Web uygulamaları gelen istekleri yeterli koruma olmadan eşzamanlı şekilde işlerken ortaya çıkarlar. Bu, aynı veriye aynı anda etkileşen birden fazla ayrı thread/invocation olması ve uygulamanın beklenmeyen davranışa girmesiyle sonuçlanabilir. Bir race condition saldırısı, kasıtlı çakışmalar  yaratmak için dikkatle zamanlanmış istekler kullanır ve bu beklenmeyen davranıştan faydalanır.
Tek kullanımlık bir hediye kartını tekrar tekrar kullanmak gibi durumlar, race condition örneklerindendir.
Çakışmanın mümkün olduğu süreye race window denir.
Diğer mantık hatalarında olduğu gibi, race condition’ın etkisi uygulamaya ve zafiyetin gerçekleştiği spesifik işlevselliğe bağlıdır.

# Race Condition Türleri
## Time-of-Check to Time-of-Use (TOCTOU)
Kaynağın kontrol edildiği an ile kullanıldığı an arasında bir değişiklik olursa.
```py
if balance >= 100:     # check
    balance -= 100     # use
```

- Kullanıcı neredeyse aynı anda iki işlem başlatır.
- Her iki işlem de 100 TL yeterli diye onay alır.
- Sonuç: balance negatif veya hatalı olur.

## State Race Condition
Sistem state’i eşzamanlı olarak değiştirildiğinde oluşur.
```py
if stock > 0:
    stock -= 1
```

- İki kullanıcı aynı anda satın alma işlemi yaparsa:
- İkisi de stok > 0 kontrolünü geçer.
- Sonuç: stok 0’ın altına düşebilir veya fazladan ürün satılmış olur.

# Race Condition Önleme Yöntemleri
## Locking / Mutex
Bir kaynağa eşzamanlı erişimi engellemek için lock mekanizması kullanılır. Tek seferde sadece bir işlem kaynağa erişebilir.
```py
from threading import Lock

balance_lock = Lock()

def transfer(amount):
    with balance_lock:
        if balance >= amount:
            balance -= amount
```

## Database Transactions
Veritabanı düzeyinde atomic, consistent, isolated, durable (ACID) özelliklerini kullanmak. Transaction sırasında kaynak başka işlem tarafından değiştirilemez.
```sql
START TRANSACTION;

SELECT balance FROM accounts WHERE id=1 FOR UPDATE;

UPDATE accounts SET balance = balance - 100 WHERE id=1;

COMMIT;
```

## Atomic Operations
Kaynağın tek bir işlemle değiştirilmesi. Ara adım olmadan işlemin tamamlanması.
```sql
UPDATE account SET balance = balance - 100 WHERE id=1 AND balance >= 100;
```