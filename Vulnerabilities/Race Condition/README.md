# Race Condition
Web uygulamaları gelen istekleri yeterli koruma olmadan eşzamanlı şekilde işlerken ortaya çıkarlar. Bu, aynı veriye aynı anda etkileşen birden fazla ayrı thread/invocation olması ve uygulamanın beklenmeyen davranışa girmesiyle sonuçlanabilir. Bir race condition saldırısı, kasıtlı çakışmalar  yaratmak için dikkatle zamanlanmış istekler kullanır ve bu beklenmeyen davranıştan faydalanır.
Tek kullanımlık bir hediye kartını tekrar tekrar kullanmak gibi durumlar, race condition örneklerindendir.
Çakışmanın mümkün olduğu süreye race window denir.
Diğer mantık hatalarında olduğu gibi, race condition’ın etkisi uygulamaya ve zafiyetin gerçekleştiği spesifik işlevselliğe bağlıdır.

## Single-packet attack
Web sunucuları, bir isteğin tüm byte’ları iletilmeden veriyi işlemeye başlamaz. Bu nedenle birkaç isteği son byte’ları gönderilmeden ilet, sonra bu son byte’ları paralel olarak göndererek tamamla. Bu teknik, single-packet attack ile geliştirildi; bu yöntem HTTP/2 protokolünü kullanır. HTTP/2’nin sunduğu multiplexing özelliği sayesinde iki tam HTTP isteği tek bir TCP paketinde gönderilebilir. Ancak yalnızca iki isteğin gönderilmesi her zaman yeterli olmayabilir; bu yüzden last-byte sync tekniği hâlâ son byte’ları göndermek için kullanılır. Bu yöntemle elde edilen sonuçlar oldukça etkilidir. Yaklaşık 1 milisaniye içinde sunucuya ulaşacak şekilde aynı anda paralel olarak 20’ye kadar istek göndermeye olanak sağlar.

