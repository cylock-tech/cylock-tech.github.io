---
layout: post
title: Emulazione di Router - Riproduzione di una PoC di una CVE tramite l'Emulazione del Firmware ASUS
author: altin_t
categories: [IoT, Emulation]
---


I device embedded e il mondo IoT diventano ogni anno più presenti nella vita quotidiana, e di conseguenza sempre più rilevanti nel mondo IT Sec. Prima di AI, prima del MetaVerso e ancora prima dei protocolli su Blockchain, l'argomento che più era trattato nel mondo IT era quello di Smart device e IoT. Potremmo dire che tutti gli argomenti sopra citati potrebbero essere in un futuro non troppo remoto, sempre più interconnessi tra di loro. Senza entrare nei meriti e demeriti, aspettivi positivi e negativi, ma solo oggettivamente parlando, tutto ciò sembra molto interessante.

Nel seguente blog viene mostrato come emulare una parte del firmware dei router ASUS per replicare la vulnerabilità CVE-2020-36109.

<br />

----

## Start ##

Nella seguente sezione viene introdotta una panoramica sugli argomenti Embedded devices, QEMU e GDB. Per saltare subito alla sezione di emulazione CVE cliccare quì: [CVE-2020-36109](#cve-2020-36109).

## Embedded devices ##

I sistemi embedded con montato sopra Linux si differenziano da un normale pc principalmente dall'hardware montatovi che è specifico per un certo dominio tramite l'ausilio di sensori ed attuatori. Il tradeof tra costi e performance è molto più rilevante rispetto ai PC, per questo motivo la memoria e CPU hanno caratteristiche limitate. Dato l'hw specifico sono necessari moduli driver specifici del produttore e quindi anche software lato user per comunicare col resto. La soluzione è quella di fornire assieme al device anche un firmware, ovvero un file compresso contente il Kernel e i file col filesystem. Il kernel può essere basato su Linux oppure altro OS. Il formato del file compresso dipende anch'esso dal vendor e può essere anche distribuito in formato non plain e quindi cifrato.

Quindi sostanzialmente per un device embedded Linux abbiamo gli stessi step di acensione per un normale PC.

<p align ="center">
  <img src="/images/2023-07/boot1.png">
</p>
<br />

----

## QEMU and GDB ##

QEMU è un emulatore che permette di emulare la parte CPU e hardware tramite software, e di conseguenza è possibile emulare un sistema operativo come un software normale. Le architetture di CPU (ISA) supportate da QEMU sono diverse, in particolare abbiamo Intel x86, ARM, e MIPS.

QEMU fornisce i seguenti modi di emulazione :

 - QEMU system emulation: Emulazione sistema operativo

<p align ="center">
  <img src="/images/2023-07/qemu1.png">
</p>
<br />

 - QEMU system emulation with KVM: Emulazione sistema operativo senza traduzione ISA, quindi l'ISA della macchina guest dev'essere uguale a quella della CPU su host

<p align ="center">
  <img src="/images/2023-07/qemu2.png">
</p>
<br />

 - QEMU user-mode emulation: Emulazione lato userspace, mentre esecuzione systemcall viene inoltrata al Kernel di host

<p align ="center">
  <img src="/images/2023-07/qemu3.png">
</p>
<br />

QEMU permette di debuggare anche il sistema emulato attraverso il componente Gdbstub che espone il protocollo GDB. GDB (GNU Project Debugger) è un debugger che supporta un'esecuzione controllata di eseguibili su Linux. Offre delle API in python che permettono di scrivere delle estensioni, le più note sono Peda, GEF, pwndbg. Nel nostro caso siamo particolarmente interessati a GDB Multiarch, il quale permette di debuggare un programma da remoto che è stato compilato per un'architettura CPU diversa da quella del nostro host.


## Gdb-multiarch + QEMU user-mode ##

Tramite l'ausilio di GDB-multiarch e QEMU user-mode è possibile monitorare l'emulazione e quindi l'esecuzione di un programma dalla stessa macchina host. Per evitare di riflettere le operazioni di syscall sul nostro filesystem usiamo chroot, il quale ci permette di cambiare il punto di mounting di "/". Infine usiamo qemu static che essendo compilato staticamente non richiede librerie esterne.

<br />

----

## CVE-2020-36109

La vulnerabilità CVE-2020-36109 viene descritta come un buffer overflow dentro il file/funzione blocking_request.cgi esposta dal servizio httpd che permetterebbe di ottenere remote code execution. Notiamo la data di disclosure 2021-01-04 ed usiamo questa informazione per ritrovare la versione del firmware corretta.

<p align ="center">
  <img src="/images/2023-07/t1.jpg">
</p>
<br />


## Firmware extraction
Facendo riferimento alla data del disclosure CVE scarichiamo due versioni del firmware: [versione unpatched](http://dlcdnet.asus.com/pub/ASUS/wireless/RT-AX86U/FW_RT_AX86U_30043849318.zip), e [versione patched](http://dlcdnet.asus.com/pub/ASUS/wireless/RT-AX86U/FW_RT_AX86U_300438641035.zip). A questo punto prendiamo la versione unpatched ed estraiamo il firmware che in questo caso risulta essere in chiaro e quindi estraiamo il tutto usando [binwalk](https://github.com/ReFirmLabs/binwalk) e [ubidump](https://github.com/nlitsme/ubidump).

<p align ="center">
  <img src="/images/2023-07/t2.png">
</p>
<br />

Il file `blocking_request.cgi` non risulta presente nel filesystem estratto, però facendo `grep -r blocking_request.cgi` vediamo che la stringa è soltanto presente dentro il file `httpd`. Questo significa che il file cgi viene direttamente implementato dal servizio httpd. Notiamo quindi l'architettura per cui è stato compilato il device essere ARM.

<p align ="center">
  <img src="/images/2023-07/t3.png">
</p>
<br />

## String analysis
Apriamo il binario httpd (non patchato) usando il decompilatore di [Ghidra](https://github.com/NationalSecurityAgency/ghidra). Siccome il servizio dovrà in qualche modo rispondere alle request HTTP dei client allora dovrà anche fornire risposte differenti a seconda del URI richiesto, e nel caso dei CGI integrati verrà usato una function table, ovvero una lista dove ogni entry contiene un puntatore ad una stringa su cui fare il string compare del URI e la funzione da invocare nel caso di compare con esito positivo. Per ricostruire già la function table e avere una versione migliore del disassemblato/decompilato usiamo lo script [codatify](https://github.com/grayhatacademy/ida/tree/master/plugins/codatify) (versione ghidra [fix_code](https://github.com/grayhatacademy/ghidra_scripts/blob/master/CodatifyFixupCode.py)).

<p align ="center">
  <img src="/images/2023-07/t4.png">
</p>
<br />

<p align ="center">
  <img src="/images/2023-07/t5.png">
</p>
<br />

<p align ="center">
  <img src="/images/2023-07/t6.png">
</p>
<br />

In particolare notiamo la stringa `"do_blocking_request_cgi"` che ci conduce alla funzione `0x48df4`. A questo punto seguiamo lo stesso iter per la versione del firmware patchato e confrontiamo i due decompilati. La funzione del decompilato patched risulta più corretta rispetto allo stack layout quindi facciamo fede ad essa come versione del decompilato più veritiera al codice sorgente. Quello che notiamo ad occhio è che nella versione patchata ci sono diverse strlcpy e che sembrano centrare coi field 'CName', 'mac', 'interval', 'timestap'. Oltre ciò notiamo delle ulteriori validazioni sui field, ciò suggerisce che probabilmente sono gli argomenti passati dalla request http del client.

<p align ="center">
  <img src="/images/2023-07/t7.png">
</p>
<br />

## Binary diffing
Per avere un quadro più preciso su quali modifiche siano state applicate sulla versione del binario patched usiamo bindiff, un tool che espone una serie di tecniche per fare binary diffing ed ottenere le differenze tra i due binari in termini di codice assembly e control flow graph. Per utilizzare bindiff con ghidra abbiamo bisogno di generare l'input adatto tramite [binexport](https://github.com/google/binexport/tree/main/java), quì vi è una guida su come fare ciò [link](https://ihack4falafel.github.io/Patch-Diffing-with-Ghidra/).

<p align ="center">
  <img src="/images/2023-07/t8.png">
</p>
<br />

Un'altro metodo per trovare punti interessanti per il task di binary diffing è quello di vedere se sono state importate nuove funzioni di libreria oppure se vengono chiamate un numero diverso di volte dentro il codice rispetto alla versione unpatched. Viene quindi quì mostrato uno script in python per svolgere tale task tramite radare2 ([link](https://gist.github.com/tin-z/0df0db7a9c396108e92da418040624c8)).

<p align ="center">
  <img src="/images/2023-07/t9.png">
</p>
<br />


## Emulation

Seguiamo quindi la rotta Gdb-multiarch + QEMU user-mode + chroot.

<p align ="center">
  <img src="/images/2023-07/t10.png">
</p>
<br />

Per esporre gdb stub su qemu usiamo il flag `-g <porta>` lanciamo quindi i seguenti comandi in due terminali separati: `sudo chroot ${PWD} ./qemu-arm-static -g 12345 bin/sh`, `sudo gdb-multiarch ./bin/busybox -q --nx -ex "source ./.gdbinit-gef.py" -ex "target remote 127.0.0.1:12345"`

<p align ="center">
  <img src="/images/2023-07/t11.png">
</p>
<br />

Tuttavia quando proviamo a lanciare httpd vengono fuori una moltitudine di eccezioni conviene quindi tracciare quali syscall vengono effettuate in modo da sistemare il filesystem chrooted. Viene usato il seguente comando: `sudo chroot ${PWD} ./qemu-arm-static -strace -D logstrace.log ./usr/sbin/httpd`. Dal file di log estraiamo i file, folder, link simbolici e librerie mancanti che dovranno poi essere fixate.

<p align ="center">
  <img src="/images/2023-07/t12.png">
  <img src="/images/2023-07/t13.png">
</p>
<br />

<p align ="center">
  <img src="/images/2023-07/t14.png">
</p>
<p align ="center">
  <img src="/images/2023-07/t15.png">
</p>
<p align ="center">
  <img src="/images/2023-07/t16.png">
</p>
<br/>

Dopo aver risolto i vari errori di file mancanti è necessario emulare anche la parte nvram, infatti i router asus caricano e scrivono le modifiche su questa memoria per tenere traccia delle configurazioni del router, come per esempio la password del wifi e il nome del modello del device. Come è possibile leggera dal log di strace, la nvram dovrebbe essere montata sul path `/jffs/nvram_war`.

Per comunicare lato client con la nvram viene usato `libnvram`, il quale espone in particolare le seguenti funzioni:

<table>
  <tr>
    <th>Function Name</th>
    <th>Description</th>
  </tr>
  <tr>
    <td><code>nvram_init()</code></td>
    <td>Initializes the libnvram library.</td>
  </tr>
  <tr>
    <td><code>nvram_get(key)</code></td>
    <td>Retrieves the value associated with <code>key</code>.</td>
  </tr>
  <tr>
    <td><code>nvram_set(key, value)</code></td>
    <td>Sets the value for the specified <code>key</code>.</td>
  </tr>
  <tr>
    <td><code>nvram_unset(key)</code></td>
    <td>Removes the entry associated with <code>key</code>.</td>
  </tr>
  <tr>
    <td><code>nvram_save()</code></td>
    <td>Saves changes made to the NVRAM configuration.</td>
  </tr>
  <tr>
    <td><code>nvram_load()</code></td>
    <td>Loads the NVRAM configuration.</td>
  </tr>
  <tr>
    <td><code>nvram_list_all()</code></td>
    <td>Lists all entries in the NVRAM configuration.</td>
  </tr>
  <tr>
    <td><code>nvram_reset()</code></td>
    <td>Resets the NVRAM configuration to defaults.</td>
  </tr>
</table>


Per ovviare questo problema viene usata la tecnica di hooking tramite LD_PRELOAD facendo cross-compilation di questa libreria: [nvram-faker](https://github.com/tin-z/nvram-faker)
Le entry chiave:valore di default vengono prese dal file `nvram.ini`, file generato da leak di utenti asus su forum e simili (e.g. "nvram show" site:pastebin.com). Lanciamo quindi i seguenti comandi `sudo chroot <path-rootfs_ubifs> ./qemu-arm-static -E LD_PRELOAD=./libnvram-faker.so -g 12345 ./usr/sbin/httpd -p 12234` e `sudo gdb-multiarch ./bin/busybox -q --nx -ex 'source ./.gdbinit-gef.py' -ex 'target remote 127.0.0.1:12345'`.

<p align ="center">
  <img src="/images/2023-07/t17.png">
</p>
<br/>

A questo punto iniziamo la fase di reversing con l'ausilio del debugger. Inserendo vari breakpoint in particolare sulle funzioni `str*` estraiamo il control flow che segue il binario. Ripetendo questo processo di reversing ibridio estraiamo le seguenti note:

<br/>

 - `0x018dcc` legge la request ed esegue il parsing iniziale (solo sezione HEAD)

<p align ="center">
  <img src="/images/2023-07/t18.png">
</p>
<br/>

 - `0x1b79c` estrae il campo dato come primo argomento dal payload della post request
 - `0x1ccb0` data una stringa in argomento ritorna il valore corrispettivo salvato prima nella nvram
 - La POST request su `blocking_request.cgi` serve per aggiungere i mac address ad una blacklist probabilmente per la connessione LAN
 - I campi `CName`, `mac`, `interval`, e `timestap` devono essere passati nella POST request
 - Per eseguire l'if corretto le seguenti condizioni devono verificarsi: la request deve avere il campo `timestap` di un valore non distante più di 21 secondi dal timestamp del router, il campo `mac` dev'essere una sottostringa del valore nvram `MULTIFILTER_MAC`


<p align ="center">
  <img src="/images/2023-07/t19.png">
</p>
<br/>


## Exploitation

La vulnerabilità risiede nella possibile esecuzione di due strcat verso un buffer su stack di dimensione fissa e l'input è dato dal client tramite i parametri POST `mac` e `timestap`.

<p align ="center">
  <img src="/images/2023-07/t20.png">
</p>
<br/>

Per triggerare la vulnerabilità dobbiamo craftare una request con le seguenti caratteristiche:
 - Il parametro `timestap` dev'essere valido, infatti viene tradotto in int tramite chiamata `atol`
 - Il parametro `mac` dev'essere substring di `MULTIFILTER_MAC` e guardando su internet questo valore sembra essere inizialmente di NULL (?), supponendo ciò sia vero, il parametro `mac` dovrà essere fissato a '%00'
 - L'overflow può solo accadere dal parametro `timestap` che però dovrà anche essere un valore valido per `atol`, risolviamo ciò usando questo valore `"<int-valido>%0a<payload>"`


<p align ="center">
  <img src="/images/2023-07/t21.png">
  <br />
  <img src="/images/2023-07/t22.png">
</p>
<br/>

Gli script per replicare l'ambiente di test e la PoC vengono forniti ai seguenti link: 
 - [PoC](https://github.com/sunn1day/CVE-2020-36109-POC)
 - [IoT toolbox repo](https://github.com/tin-z/IoT_toolbox/tree/main/pocs/ASUS)


### Considerazioni ###

Limitazioni exploit:
 - L'overflow accade tramite `str*` quindi non possiamo usare null dentro il payload
 - Il payload si trova subito sotto all'epilogo dello stack, quindi non possiamo corrompere altre strutture dati se non il return address
 - C'è stack canary, e per i motivi di prima, anche guessando in qualche modo il canarino se esso ha il nullbyte allora diventa impossibile sovrascrivere il return address
 - Lo stack canary contiene null

Make exploit great again:
 - Tuttavia nel caso in cui il valore nvram `MULTIFILTER_MAC` contiene un qualsiasi char ascii, ciò permetterebbe di sbufferare prima con parametro `mac` e poi `timestap`, unendo ciò possiamo sovrascrivere il return address e creare una ROP
 - I router asus lanciano httpd come demone, quindi il processo che assiste il client è un child di parent, questo significa che eredita lo stesso space address e quindi possiamo facilmente fare bruteforce di canary e base addresses per la ROP


Patch:
 - Come descritto prima, la patch consiste nel limitare la size dei parametri POST tramite `strlcpy`.



