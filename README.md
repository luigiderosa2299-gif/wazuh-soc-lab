# Wazuh SOC Lab: detection engineering, vulnerability assessment e hardening CIS

> ⚠️ **Disclaimer etico.** Tutti i test sono stati eseguiti su macchine virtuali di mia proprietà, in una rete di laboratorio. Atomic Red Team esegue tecniche offensive reali: non usarlo su sistemi che non ti appartengono o senza autorizzazione scritta.

## 📌 Obiettivo

Costruire un piccolo SOC domestico e usarlo per tre attività tipiche di un analista: verificare cosa rileva un SIEM per default, scrivere regole di detection dove manca la copertura, e misurare il prima/dopo di patching e hardening. Moduli Security+ coinvolti: monitoraggio e logging, gestione delle vulnerabilità, hardening, framework MITRE ATT&CK.

## 🧩 Contesto

- **Server**: Wazuh 4.14.1 all-in-one (manager, indexer, dashboard) su Ubuntu Server 24.04 ARM, VM UTM.
- **Endpoint**: Windows 11 Home (ARM, build 26200) con agente Wazuh 4.14.1 e Sysmon.
- **Generatore di attività**: Atomic Red Team (Invoke-AtomicRedTeam 2.1.0).

## 🛠 Tecnologie

Wazuh (SIEM, Vulnerability Detection, SCA), Sysmon, Atomic Red Team, MITRE ATT&CK, CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0, PowerShell, winget.

## ⚙️ Cosa ho fatto

1. Installato Wazuh con lo script `wazuh-install.sh -a` e collegato l'agente Windows.
2. Verificato la pipeline con eventi semplici (creazione utente locale, logon falliti): regole 60109, 60122, ecc.
3. Installato Sysmon e collegato il suo canale eventi a Wazuh.
4. Eseguito tecniche Atomic Red Team una alla volta, sempre con `-TestNumbers`, seguendo il ciclo `-ShowDetailsBrief` → esecuzione → `-Cleanup`: T1033, T1082, T1087.001, T1069.001, T1016, T1049, T1057, T1053.005, T1547.001.
5. Letto in Wazuh cosa generava ogni tecnica con le regole di default e individuato le lacune di copertura (vedi Risultati).
6. Scritto 10 regole custom (ID 100100-100109) in `rules/`, che estendono le regole Sysmon di Wazuh con controlli sulla riga di comando. Le ho caricate dal dashboard (Server management → Rules) e riavviato il manager.
7. Rieseguito i test e confrontato gli alert prima e dopo.
8. Lanciato la scansione Vulnerability Detection, applicato le patch con `winget upgrade` e ripetuto la scansione.
9. Usato SCA (policy CIS Windows 11 Enterprise) per estrarre i controlli falliti, scelto 27 controlli sicuri (password e blocco account, chiavi di registro, servizi inutili), applicati con `net accounts`, e `Set-ItemProperty` sul registro (anche `Start=4` per disattivare i servizi), e riavviato l'agente per forzare una nuova scansione.

## 📊 Risultati

### Detection engineering

| Tecnica | Regola di default | Regola custom |
|---|---|---|
| T1053.005 (task pianificato di persistenza) | 92032, livello 3, tag generico T1087 | **100100**, livello 10 |
| T1016 (ipconfig/arp/nbtstat) | 92032, livello 3 | **100101**, livello 6 |
| T1049 (netstat) | 92032, livello 3 | **100102**, livello 6 |
| T1087.001 (`query user`) | 92052, livello 4 | **100103**, livello 6 |
| T1069.001 (gruppi locali) | 92036/92031 (3), 92027 (4) | **100104**, **100105**, livello 6 |
| T1057 (processi) | 92032 (3), 92027/92052 (4) | **100106-100108** (6), **100109** (8) |
| T1547.001 (chiave Run) | 92302, livello 6, tag corretto | nessuna regola necessaria |

Senza le regole custom, la creazione di un task pianificato come SYSTEM all'avvio (T1053.005) produceva solo un alert di livello 3 con tecnica sbagliata.

**Falsi positivi osservati**
- La regola 92213 (livello 15, T1105) scatta a ogni avvio di PowerShell: segnala un eseguibile/script in `AppData\Local\Temp`.
- La regola 92041 (livello 10) ha segnalato come "Base64-like" il percorso `C:\Path\AtomicRedTeam.exe`.
- La regola 92058 (livello 12, `sdbinst.exe -m -bg`) è risultata attività di manutenzione di Windows.

**Limiti delle regole custom**
- Leggono solo il testo della riga di comando: non coprono comandi offuscati o in Base64, né strumenti che usano API senza lanciare processi.
- I livelli (6, 8, 10) sono una mia scelta per rendere gli eventi visibili. Su una macchina reale servirebbe una taratura per evitare rumore.

### Vulnerability Detection

![Vulnerability Detection e SCA prima delle modifiche](img/vuln-sca-before.png)

| | Totale | Critical | High | Medium | Low |
|---|---|---|---|---|---|
| Scansione 1 | 121 | 0 | 19 | 93 | 9 |
| Scansione 2 (dopo patch) | 16 | 0 | 7 | 8 | 1 |

- Wireshark 4.6.4 → 4.6.9: 103 CVE chiuse (11 High).
- Aggiornati anche Python (3.15.0 → 3.15.2) e il QEMU guest agent; il pacchetto QEMU non compare più tra i risultati.

### Hardening CIS (SCA)

![Punteggio SCA dopo l'hardening](img/sca-after-hardening.png)

| | Superati | Falliti | Score |
|---|---|---|---|
| Prima | 114 | 358 | 24% |
| Dopo | 141 | 331 | 29% |

Il confronto tra l'export dei controlli falliti prima e quello dei superati dopo mostra esattamente 27 controlli passati a *Passed*, gli stessi che avevo applicato (elenco in `data/cis-controls-fixed.csv`). Nessun altro controllo è cambiato.

**Limite**: il benchmark è per Enterprise e la VM è Home. Molti controlli sono già superati perché la funzione non è installata, quindi lo score complessivo non misura l'hardening reale. Il dato significativo è il delta dei 27 controlli modificati.

## 💡 Cosa ho imparato

- Le regole di default di Wazuh per Sysmon riconoscono l'esecuzione di `cmd.exe` o PowerShell, ma assegnano tecniche e livelli generici: la copertura di una tecnica ATT&CK specifica va verificata con un test, non data per scontata.
- Una regola figlia (`if_sid`) con un filtro `pcre2` sulla riga di comando è sufficiente per dare livello e tecnica corretti a un comportamento noto, ma resta aggirabile con l'offuscamento.
- Il livello 15 non indica per forza un attacco: una singola regola troppo larga (92213) può generare alert massimi a ogni avvio di PowerShell.
- La scansione delle vulnerabilità si basa sull'inventario del software e sul confronto di versioni: dopo una patch l'inventario va rigenerato (riavvio dell'agente) prima di rilanciare la scansione.
- Il punteggio SCA dipende dall'edizione del sistema rispetto al benchmark. Conviene riportare i controlli cambiati, non solo la percentuale.

## 🔗 Collegamenti

- [Wazuh documentation](https://documentation.wazuh.com/)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
