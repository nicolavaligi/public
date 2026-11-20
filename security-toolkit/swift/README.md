# Audit difensivi in Swift

I due strumenti leggono file locali. Compilali con Swift su macOS.

```sh
swiftc audit_certificato.swift -o /tmp/audit_certificato
swiftc audit_docker.swift -o /tmp/audit_docker
```

## Scadenza di un certificato

```sh
/tmp/audit_certificato certificato.pem 30
```

Lo script legge la data di scadenza di un singolo certificato con `/usr/bin/openssl`. La soglia predefinita è 30 giorni. Il controllo copre la scadenza. La catena di fiducia, il nome dell'host e la revoca richiedono verifiche distinte.

## Configurazione di un container Docker

```sh
docker inspect --type container nome-container > inspect.json
/tmp/audit_docker inspect.json
```

Lo script segnala modalità privilegiata, condivisione dei namespace PID o IPC dell'host, capability sensibili aggiunte e mount associati a `docker.sock`. Esegue un controllo mirato della configurazione e legge l'export senza connettersi al daemon. Gli export reali possono contenere variabili d'ambiente con segreti. Tienili fuori dal repository.

Entrambi restituiscono 0 quando i controlli passano, 1 quando rilevano un problema e 2 per errori di input o di esecuzione.

## Difesa di rete

```sh
swiftc audit_rete.swift -o /tmp/audit_rete

# Listener TCP locali. Inserisci solo le porte ammesse dalla tua configurazione.
lsof -nP -iTCP -sTCP:LISTEN -F n > listener.txt
/tmp/audit_rete porte listener.txt 443

# Nomi che devono essere risolti senza un override locale.
/tmp/audit_rete hosts /etc/hosts github.com example.com
```

`porte` segnala i listener fuori loopback la cui porta manca dall'elenco delle porte ammesse. Senza porte in argomento, segnala tutti i listener fuori loopback presenti nell’export. La visibilità di `lsof` dipende dai permessi con cui è stato eseguito. Controlla che la raccolta sia riuscita prima di usare il risultato. L’audit riguarda i bind locali. La raggiungibilità dalla rete dipende anche dal firewall e dalla topologia.

`hosts` cerca corrispondenze esatte, senza distinzione tra maiuscole e minuscole, tra gli alias del file e i nomi indicati. Gli override intenzionali richiedono un riscontro con la configurazione prevista. Entrambi i controlli leggono i file in locale e usano gli stessi codici di uscita degli altri audit.
