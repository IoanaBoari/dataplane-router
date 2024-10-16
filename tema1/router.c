#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "queue.h"
#include "lib.h"
#include "protocols.h"


	/* Routing table */
	struct route_table_entry *rtable;
	int rtable_len;

	struct arp_table_entry *arptable;
	int arptable_len;

// Structura pentru un nod în arborele binar de căutare
struct node {
    struct route_table_entry *entry;
    struct node *left;
    struct node *right;
};

// Funcția de creare a unui nod pentru arbore
struct node* create_node(struct route_table_entry *entry) {
    struct node* new_node = (struct node*)malloc(sizeof(struct node));
    new_node->entry = entry;
    new_node->left = NULL;
    new_node->right = NULL;
    return new_node;
}

// Funcția de inserare a unei intrări în arbore
struct node* insert_node(struct node* root, struct route_table_entry* entry) {
    if (root == NULL)
        return create_node(entry);

    uint32_t prefix = entry->prefix;
    uint32_t mask = entry->mask;
    uint32_t root_prefix = root->entry->prefix;
    uint32_t root_mask = root->entry->mask;

    // Comparam prefixul curent cu cel al nodului radacina
    if ((prefix & mask) < (root_prefix & root_mask))
        root->left = insert_node(root->left, entry);
    else
        root->right = insert_node(root->right, entry);

    return root;
}

// Funcția de căutare a celei mai bune rute în arbore
struct route_table_entry* search_route(struct node* root, uint32_t ip_dest) {
    struct route_table_entry *best_route = NULL;
    uint32_t longest_mask = 0;

    // Parcurgem arborele binar de căutare
    while (root != NULL) {
        uint32_t entry_prefix = root->entry->prefix & root->entry->mask;
        uint32_t entry_mask = root->entry->mask;

        uint32_t entry_prefix_host = ntohl(entry_prefix);
        uint32_t ip_dest_host = ntohl(ip_dest);
        uint32_t entry_mask_host = ntohl(entry_mask);

        // Verificam dacă adresa IP a destinatarului se potrivește cu intrarea din tabel
        if ((entry_prefix_host == (ip_dest_host & entry_mask_host)) && (entry_mask_host >= longest_mask)) {
            best_route = root->entry;
            longest_mask = entry_mask_host;
        }

        // Dacă prefixul intrării este mai mare decât adresa IP destinatarului, mergem la stânga în arbore
        if ((ip_dest & entry_mask) < (entry_prefix & entry_mask))
            root = root->left;
        // Altfel, mergem la dreapta în arbore
        else
            root = root->right;
    }

    return best_route;
}

// Funcția de eliberare a memoriei alocate pentru arbore
void free_tree(struct node* root) {
    if (root != NULL) {
        free_tree(root->left);
        free_tree(root->right);
        free(root);
    }
}


struct arp_table_entry *get_arp_entry(uint32_t given_ip) {
    // Parcurgem fiecare intrare din tabela ARP
	for (int i = 0; i < arptable_len; i++) {
        struct arp_table_entry *entry = &arptable[i];
        // Verificăm dacă adresa IP din intrarea curentă este cea căutată
        if (entry->ip == given_ip) {
            return entry;
        }
    }

	return NULL;
}

// Functia modifică bufferul pentru a crea un mesaj ICMP de tipul specificat
void icmp(char *buf, size_t *len, uint32_t router_ip, uint8_t type) {
    // Extragem antetul IPv4 și antetul ICMP din buffer
	struct iphdr *ip_hdr = (struct iphdr *) (buf + sizeof(struct ether_header));
	struct icmphdr *icmp_hdr = (struct icmphdr *) (buf + sizeof(struct ether_header) + sizeof(struct iphdr));

    // Alocăm memorie pentru datele ICMP
	char *icmp_content = malloc(sizeof(struct iphdr) + 8); // 8 reprezinta primii 64 de biți(8 octeti) din payload-ul pachetului original

    *len += sizeof(struct icmphdr) + sizeof(struct iphdr) + 8; // Actualizam lungimea buffer-ului

    // Salvam antetul IPv4 original și următorii 64 de biți
	memcpy(icmp_content, ip_hdr, sizeof(struct iphdr) + 8);

    // Modificăm antetul IPv4 pentru a trimite mesajul ICMP
	ip_hdr->daddr = ip_hdr->saddr; // Setam destinația către expeditor
	ip_hdr->saddr = router_ip; // Setam sursa ca IP-ul routerului
	ip_hdr->ttl = 64; // Resetam TTL-ul
	ip_hdr->tot_len += sizeof(struct icmphdr) + sizeof(struct iphdr) + 8; // Actualizam lungimea totală
	ip_hdr->protocol = 1; // Pachetul ICMP este încapsulat

    // Recalculam checksum pentru antetul IPv4
	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

    // Construim antentul ICMP
	memset(icmp_hdr, 0, sizeof(struct icmphdr));
	icmp_hdr->type = type;
	icmp_hdr->code = 0;  // codul este 0 pentru cele 3 tipuri de mesaje pe care le poate intoarce protocolul icmp 

    // Calculam checksum pentru antentul ICMP
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *) icmp_hdr, sizeof(struct icmphdr)));

    // Încapsulam antetul IPv4 original + 64 de biți în mesajul ICMP
	memcpy(buf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), icmp_content, sizeof(struct iphdr) + 8);

	free(icmp_content);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	/* Alocam memorie pentru tabela de rutare*/
	rtable = malloc(sizeof(struct route_table_entry) * 65000);
	/* Verificam dacă alocarea memoriei a fost realizată cu succes*/
	DIE(rtable == NULL, "memory error");
	
	/* Citim tabela statica de rutare*/
	rtable_len = read_rtable(argv[1], rtable);

    // Inițializam arborele binar de căutare
    struct node *root = NULL;

    // Inserăm fiecare intrare din tabela de rutare în arbore
     for (int i = 0; i < rtable_len; i++) {
        root = insert_node(root, &rtable[i]);
     }

	// Alocam memorie pentru tabela ARP
    arptable = malloc(sizeof(struct arp_table_entry) * 10);
    // Verificam dacă alocarea memoriei a fost realizată cu succes
    DIE(arptable == NULL, "memory error");
    // Parsam fișierul "arp_table.txt" și stocam intrările în tabela ARP recent alocata
    arptable_len = parse_arp_table("arp_table.txt", arptable);

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		
		struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

		/* Verificăm dacă am primit un pachet diferit de IPv4 */
		if (eth_hdr->ether_type != ntohs(ETHERTYPE_IP)) {
			printf("Ignored non-IPv4 packet\n");
			continue;
		}

        // Obținem adresa IP a routerului pe interfața specificată
        uint32_t router_ip = inet_addr(get_interface_ip(interface));


        // Verificăm dacă valoarea TTL-ului din header-ul IP este mai mică sau egală cu 1
		if (ip_hdr->ttl <= 1) {
            // trimitem un mesaj ICMP pentru expirarea campului TTL
            icmp(buf, &len, router_ip, ICMP_TIME_EXCEEDED);
		}

        // Salvăm valoarea veche a checksum-ului IP pentru verificare
        uint16_t old_checksum = ntohs(ip_hdr->check);
		ip_hdr->check = 0;

        // Verificăm dacă checksum-ul recalculat al header-ului IP este diferit de checksum-ul original
		if (checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)) != old_checksum) {
			continue;
		}

        // Restaurăm checksum-ul original al header-ului IP
        ip_hdr->check = htons(old_checksum);

    
        // Recalculam checksum-ul conform formulei din laboratorul 4
        uint8_t old_ttl = ip_hdr->ttl;
		ip_hdr->ttl--;
        ip_hdr->check = ~(~ip_hdr->check +  ~((uint16_t)old_ttl) + (uint16_t)ip_hdr->ttl) - 1;


        // Verificăm dacă adresa destinatarului din header-ul IP este adresa IP a routerului
        if (ip_hdr->daddr == router_ip) {
            // trimitem un mesaj ICMP de tip reply pentru un mesaj icmp primit de tip request
            icmp(buf, &len, router_ip, ICMP_ECHOREPLY);
        }

        // Căutăm cea mai bună rută în arborele de rute pentru adresa destinatarului din header-ul IP
		struct route_table_entry *best_route = search_route(root, ip_hdr->daddr);
		if (!best_route) {
            // trimitem un mesaj icmp pentru cazul in care nu se gaseste ruta pana la destinatie
            icmp(buf, &len, router_ip, ICMP_DEST_UNREACHABLE);
            best_route = search_route(root, ip_hdr->daddr);
		}

        // Obținem intrarea ARP corespunzătoare următorului hop din cea mai bună rută
		struct arp_table_entry *arp_entry = get_arp_entry(best_route->next_hop);
        
        // Declaram un vector pentru adresa MAC a sursei
        uint8_t source_mac[6];

        // Obținem adresa MAC a interfeței asociate celei mai bune rute
        get_interface_mac(best_route->interface, source_mac);

        for(int i = 0; i < 6; i++){
            // Copiem adresa MAC a destinatarului și a sursei în header-ul Ethernet
			eth_hdr->ether_dhost[i] = arp_entry->mac[i];
			eth_hdr->ether_shost[i] = source_mac[i];
		}

        // Trimitem pachetul către interfața asociată celei mai bune rute
		send_to_link(best_route->interface, buf, len);

    }
        // Eliberam memoria alocata in timpul programului
        free(rtable);
        free(arptable);
        free_tree(root);

		return 0;
}