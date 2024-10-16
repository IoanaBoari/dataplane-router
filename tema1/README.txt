// BOARI Ioana-Ruxandra 322CD

            PCOM Tema 1 - Dataplane Router

    Am implementat subcerintele:
- Procesul de dirijare
- Longest Prefix Match eficient
- Protocolul ICMP

    Pentru a implementa dataplane-ul pentru un router am avut nevoie de cateva structuri suplimentare.

    Am ales sa folosesc un arbore binar de cautare pentru a cauta ruta cea mai potrivita 
deoarece complexitatea este mai redusa, fiind logaritmica, in comparatie cu cautarea liniara.

     get_arp_entry am implementat-o pentru a obtine adresa MAC a urmatorului hop din ruta.

    Funcția icmp construiește un mesaj ICMP pe baza datelor primite în buffer.
Extrage antetul IPv4 și antetul ICMP, apoi alocă memorie pentru datele ICMP. 
Modifică antetul IPv4 pentru a transmite mesajul ICMP, recalculează checksum-urile 
și încapsulează datele originale în mesajul ICMP. 
La final, eliberează memoria alocată. Această funcție facilitează generarea 
și trimiterea de mesaje ICMP din cadrul routerului.

    În funcția main, programul inițializează parametrii și alocă memoria pentru 
tabela de rutare și pentru tabela ARP. Tabela de rutare este citită din fișier,
iar apoi fiecare intrare este inserată într-un arbore binar de căutare. 
De asemenea, se alocă și parsează tabela ARP. Aceste operațiuni pregătesc 
datele necesare pentru procesarea pachetelor în cadrul routerului.
În bucla while(1), programul primește pachete de date de la orice interfață 
disponibilă și le procesează pentru rutare. Verifică dacă pachetul este de tip IPv4
și dacă are TTL-ul suficient de mare. Daca TTL-ul este <=1 atunci se intoarce 
un mesaj de tip ICMP la expeditor. Apoi, verifica checksum-ul, actualizează TTL-ul 
și recalculează checksum-ul. Dacă adresa IP de destinație este cea a routerului, 
se răspunde cu un mesaj ICMP. În caz contrar, se caută cea mai bună rută în
arborele binar de cautare pentru rute. Apoi se obtine adresa MAC a urmatorului
hop din ruta si a interfetei asociate. Apoi, se actualizează adresele MAC ale
surselor și destinației în header-ul Ethernet pentru a reflecta adresele corespunzătoare.
In final, se trimite pachetul si se eliberează memoria alocată.

    La rularea locala obtin: 70 pct