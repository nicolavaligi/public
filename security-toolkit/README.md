# Security Toolkit

Due script difensivi per macOS e Linux. Richiedono Python 3.11 o successivo e usano la libreria standard.

```sh
python3 audit_permissions.py ./config
python3 integrity.py capture ./config ./config.sha256.json
python3 integrity.py check ./config ./config.sha256.json
```

- **Permessi** segnala file regolari e directory scrivibili da qualunque utente secondo i bit POSIX. Il controllo riguarda i bit di modalità, con ACL e sticky bit esclusi dalla valutazione.
- **Integrità** rileva aggiunte, rimozioni e cambiamenti nel contenuto dei file regolari. Crea il manifest su un albero noto e stabile e conservalo in una posizione fidata, esterna all'albero. La creazione richiede un nuovo percorso.

Gli script saltano i link simbolici e sono pensati per alberi locali stabili durante la scansione. Gli esiti sono 0 per operazione riuscita senza rilievi, 1 per rilievi e 2 per errori.
