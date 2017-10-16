/***************************************************************************
 practica2.c
 Muestra las direciones Ethernet de la traza que se pasa como primer parametro.
 Debe complatarse con mas campos de niveles 2, 3, y 4 tal como se pida en el enunciado.
 Debe tener capacidad de dejar de analizar paquetes de acuerdo a un filtro.

 Compila: gcc -Wall -o practica2 practica2.c -lpcap, make
 Autor: Jose Luis Garcia Dorado, Jorge E. Lopez de Vergara Mendez, Rafael Leira
 2017 EPS-UAM
***************************************************************************/

#include <stdio.h>
#include <stdlib.h>

#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <signal.h>
#include <time.h>
#include <getopt.h>
#include <inttypes.h>

/*Definicion de constantes *************************************************/
#define ETH_ALEN      6      /* Tamanio de la direccion ethernet           */
#define ETH_HLEN      14     /* Tamanio de la cabecera ethernet            */
#define ETH_TLEN      2      /* Tamanio del campo tipo ethernet            */
#define ETH_FRAME_MAX 1514   /* Tamanio maximo la trama ethernet (sin CRC) */
#define ETH_FRAME_MIN 60     /* Tamanio minimo la trama ethernet (sin CRC) */
#define ETH_DATA_MAX  (ETH_FRAME_MAX - ETH_HLEN) /* Tamano maximo y minimo de los datos de una trama ethernet*/
#define ETH_DATA_MIN  (ETH_FRAME_MIN - ETH_HLEN)
#define IP_ALEN 4	     /* Tamanio de la direccion IP		   */
#define OK 0
#define ERROR 1
#define PACK_READ 1
#define PACK_ERR -1
#define TRACE_END -2
#define NO_FILTER 0
#define MAXBUF 512

/*Funciones definidas*/
void analizar_paquete(const struct pcap_pkthdr *hdr, const uint8_t *pack);

void handleSignal(int nsignal);

/*Variables globales*/
pcap_t *descr = NULL;
uint64_t contador = 0;
int paquetes_filtrados =0;
uint8_t flagIpo = 0;
uint8_t flagIpd = 0;
uint8_t flagPo = 0;
uint8_t flagPd = 0;
uint8_t ipsrc_filter[IP_ALEN] = {NO_FILTER};
uint8_t ipdst_filter[IP_ALEN] = {NO_FILTER};
uint16_t sport_filter= NO_FILTER;
uint16_t dport_filter = NO_FILTER;

void handleSignal(int nsignal){
	(void) nsignal; // indicamos al compilador que no nos importa que nsignal no se utilice

	printf("\nControl C pulsado (%"PRIu64" paquetes leidos)\n", contador);
	printf("Paquetes impresos completos: %d\n\n", paquetes_filtrados);
	pcap_close(descr);
	exit(OK);
}

int main(int argc, char **argv){
	uint8_t *pack = NULL;
	struct pcap_pkthdr *hdr;

	char errbuf[PCAP_ERRBUF_SIZE];
	char entrada[256];
	int long_index = 0, retorno = 0;
	char opt;
	

	if (signal(SIGINT, handleSignal) == SIG_ERR) {
		printf("Error: Fallo al capturar la senal SIGINT.\n");
		exit(ERROR);
	}

	if (argc > 1) {
		if (strlen(argv[1]) < 256) {
			strcpy(entrada, argv[1]);
		}

	} else {
		printf("Ejecucion: %s <-f traza.pcap / -i eth0> [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]\n", argv[0]);
		exit(ERROR);
	}

	static struct option options[] = {
		{"f", required_argument, 0, 'f'},
		{"i",required_argument, 0,'i'},
		{"ipo", required_argument, 0, '1'},
		{"ipd", required_argument, 0, '2'},
		{"po", required_argument, 0, '3'},
		{"pd", required_argument, 0, '4'},
		{"h", no_argument, 0, '5'},
		{0, 0, 0, 0}
	};

	//Simple lectura por parametros por completar casos de error, ojo no cumple 100% los requisitos del enunciado!
	while ((opt = getopt_long_only(argc, argv, "f:i:1:2:3:4:5", options, &long_index)) != -1) {
		switch (opt) {
		case 'i' :
			if(descr) { // comprobamos que no se ha abierto ninguna otra interfaz o fichero
				printf("Ha seleccionado más de una fuente de datos\n");
				pcap_close(descr);
				exit(ERROR);
			}
			//printf("Descomente el código para leer y abrir de una interfaz\n");
			//exit(ERROR);
			
			//if ( (descr = ??(optarg, ??, ??, ??, errbuf)) == NULL){
			//	
			//	exit(ERROR);
			//}
			
			if ((descr = pcap_open_live(optarg, MAXBUF,0,100, errbuf)) == NULL){
		    		printf("Error: pcap_open_live(): Interface: %s, %s %s %d.\n", optarg,errbuf,__FILE__,__LINE__);
		   		exit(ERROR);
	   		}
			break;

		case 'f' :
			if(descr) { // comprobamos que no se ha abierto ninguna otra interfaz o fichero
				printf("Ha seleccionado más de una fuente de datos\n");
				pcap_close(descr);
				exit(ERROR);
			}
			//printf("Descomente el código para leer y abrir una traza pcap\n");
			//exit(ERROR);

			if ((descr = pcap_open_offline(optarg, errbuf)) == NULL) {
				printf("Error: pcap_open_offline(): File: %s, %s %s %d.\n", optarg, errbuf, __FILE__, __LINE__);
				exit(ERROR);
			}

			break;

		case '1' :
			flagIpo = 1;
			if (sscanf(optarg, "%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8"", &(ipsrc_filter[0]), &(ipsrc_filter[1]), &(ipsrc_filter[2]), &(ipsrc_filter[3])) != IP_ALEN) {
				printf("Error ipo_filtro. Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
				exit(ERROR);
			}

			break;

		case '2' :
			flagIpd = 1;
			if (sscanf(optarg, "%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8"", &(ipdst_filter[0]), &(ipdst_filter[1]), &(ipdst_filter[2]), &(ipdst_filter[3])) != IP_ALEN) {
				printf("Error ipd_filtro. Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
				exit(ERROR);
			}

			break;

		case '3' :
			flagPo = 1;
			if ((sport_filter= atoi(optarg)) == 0) {
				printf("Error po_filtro.Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
				exit(ERROR);
			}

			break;

		case '4' :
			flagPd = 1;
			if ((dport_filter = atoi(optarg)) == 0) {
				printf("Error pd_filtro. Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
				exit(ERROR);
			}

			break;

		case '5' :
			printf("Ayuda. Ejecucion: %s <-f traza.pcap / -i eth0> [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
			exit(ERROR);
			break;

		case '?' :
		default:
			printf("Error. Ejecucion: %s <-f traza.pcap / -i eth0> [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
			exit(ERROR);
			break;
		}
	}

	if (!descr) {
		printf("No selecciono ningún origen de paquetes.\n");
		return ERROR;
	}

	//Simple comprobacion de la correcion de la lectura de parametros
	printf("Filtro:");
	//if(ipsrc_filter[0]!=0)
	printf("ipsrc_filter:%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\t", ipsrc_filter[0], ipsrc_filter[1], ipsrc_filter[2], ipsrc_filter[3]);
	//if(ipdst_filter[0]!=0)
	printf("ipdst_filter:%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\t", ipdst_filter[0], ipdst_filter[1], ipdst_filter[2], ipdst_filter[3]);

	if (sport_filter!= NO_FILTER) {
		printf("po_filtro=%"PRIu16"\t", sport_filter);
	}

	if (dport_filter != NO_FILTER) {
		printf("pd_filtro=%"PRIu16"\t", dport_filter);
	}

	printf("\n\n");

	do {
		retorno = pcap_next_ex(descr, &hdr, (const u_char **)&pack);

		if (retorno == PACK_READ) { //Todo correcto
			contador++;
			analizar_paquete(hdr, pack);
			printf("\n\n");
		
		} else if (retorno == PACK_ERR) { //En caso de error
			printf("Error al capturar un paquetes %s, %s %d.\n", pcap_geterr(descr), __FILE__, __LINE__);
			pcap_close(descr);
			exit(ERROR);

		}
	} while (retorno != TRACE_END);

	printf("Se procesaron %"PRIu64" paquetes.\n\n", contador);
	printf("Paquetes que han pasado el filtro: %d\n\n", paquetes_filtrados);
	pcap_close(descr);
	return OK;
}



void analizar_paquete(const struct pcap_pkthdr *hdr, const uint8_t *pack){	
	char buffer[MAXBUF];
	uint8_t version = 0;
	uint16_t port = 0;
	uint16_t longitudUDP = 0;
	uint16_t tlength = 0;
	uint16_t posic = 0;
	int flag = 0;
	int UDP0_TCP1 = 0; /*Aqui almacenaremos el tipo de protocolo de la capa 4 */
	int i = 0;

	printf("Nuevo paquete capturado el %s\n", ctime((const time_t *) & (hdr->ts.tv_sec)));

	printf("Numero de paquete: %"PRIu64"\n", contador);
	
	//CAPA 2
	printf("CAPA 2\n");

	printf("Direccion ETH destino = ");
	printf("%02X", pack[0]);

	for (i = 1; i < ETH_ALEN; i++) {
		printf(":%02X", pack[i]);
	}

	printf("\n");
	pack += ETH_ALEN;

	printf("Direccion ETH origen = ");
	printf("%02X", pack[0]);

	for (i = 1; i < ETH_ALEN; i++) {
		printf(":%02X", pack[i]);
	}

	printf("\n");
	pack+=ETH_ALEN;

	printf("Protocolo = 0x");

	for (i = 0; i < ETH_TLEN; i++) {
		printf("%02X", pack[i]);
		sprintf(buffer+2*i, "%02X", pack[i]);
	}

	if(strcmp(buffer, "0800")){
		printf("\nError: protocolo no reconocido\n"); /*El protocolo no es IPv4 asi que no imprimimos las siguientes capas*/
		return;	
	} 
	else {
		printf(" (IPv4)\n");
	}

	printf("\n");

	//CAPA 3
	printf("CAPA 3\n");

	pack += ETH_TLEN;

	printf("Version IP = ");
	memcpy(&version, pack, 1);
	sprintf(buffer, "0%x", version);
	char IHL = buffer[2];
	buffer[2]=0;
	printf("%d\n", (int)strtol(buffer, NULL, 10));

	printf("Longiud de cabecera = %d bytes\n", (int)strtol(&IHL, NULL, 10)*4);

	pack += 2; /*Saltamos Version, IHL y Tipo de Servicio, un total de 2 bytes*/
	memcpy(&tlength, pack, 2);	
	printf("Longitud total = %u\n", ntohs(tlength));
	

	pack += 4;
	memcpy(&posic, pack, 2);
	posic = ntohs(posic);
	posic = posic & 8191; /*Hacemos AND con 0001111111111111 que en decimal es 8191 para poner los primeros 3 bits que son de otro campo a 0*/
	printf("Posicion/Desplazamiento = %u\n", posic*8);
	if(posic != 0){
		flag = 1; /*El desplazamiento es distinto de 0*/
	}

	pack += 2;
	printf("Tiempo de vida = %u\n", *pack);

	pack += 1;
	printf("Protocolo = %u", *pack);
	if(*pack == 6){
		printf(" (TCP)\n");
		UDP0_TCP1 = 1; /*Ponemos el flag a 1 porque es de tipo TCP*/
	} 
	else if(*pack == 17) {
		printf(" (UDP)\n");
		UDP0_TCP1 = 0; /*Ponemos el flag a 0 porque es de tipo UDP*/
	} 
	else {
		flag = 1; /*No se trata de un protocolo TCP ni de un protocolo UDP*/
		printf(" Error: protocolo no reconocido\n\n");
	}
	
	pack += 3;

		
	printf("Direccion IP de origen = %u", *pack);
	for (i = 1; i < 4; i++) {
		printf(".%u", pack[i]);
	}
	
	if(flagIpo == 1){
		for(i=0;i<4;i++){
			if(pack[i]!=ipsrc_filter[i]){
				printf("\nLa direccion origen no coincide con la del filtro, deshechando paquete\n\n");
				return;
			}
		}
	}
		
					
	pack += 4;
	printf("\nDireccion IP de destino = %u", *pack);
	for (i = 1; i < 4; i++) {
		printf(".%u", pack[i]);
	}
	
	if(flagIpd == 1){
		for(i=0;i<4;i++){
			if(pack[i]!=ipdst_filter[i]){
				printf("\nLa direccion de destino no coincide con la del filtro, deshechando paquete\n\n");
				return;
			}
		}
	}
	
	
	printf("\n");
	if(flag == 1){
		return; /*El desplazamiento es distinto de 0 o el protocolo no es UDP ni TCP asi que no imprimimos los campos de la siguiente capa*/
	}

	if((int)strtol(&IHL, NULL, 10)*4 > 20){
		pack += 8;
	} else {
		pack += 4;
	}

	printf("\n");

	//CAPA 4
	printf("CAPA 4\n");

	memcpy(&port, pack, 2);	
	port = ntohs(port);
	printf("Puerto de origen = %u\n", port);
	if(flagPo==1){
		if(port!=sport_filter){
			printf("El puerto de origen no coincide con el del filtro, deshechando paquete\n\n");
			return;
		}
	}
	
	pack += 2;
	memcpy(&port, pack, 2);
	port = ntohs(port);
	printf("Puerto de destino = %u\n", port);
	if(flagPd==1){
		if(port!=dport_filter){
			printf("El puerto de destino no coincide con el del filtro, deshechando paquete\n\n");
			return;
		}
	}
	
	/*El paquete es de tipo UDP*/
	if(UDP0_TCP1==0){ 
		pack += 2;
		memcpy(&longitudUDP, pack, 2);
		longitudUDP = ntohs(longitudUDP);
		printf("Longitud = %u\n", longitudUDP);	
	} 
	/*El paquete es de tipo TCP*/
	else { 
		pack += 11;
		if((*pack & 16) > 0){ /*Hacemos AND con 00010000 que en decimal es 16 para ver si el campo ACK esta a 0 o a 1*/
			printf("ACK = 1\n");
		} else {
			printf("ACK = 0\n");
		}
		
		if((*pack & 2) > 0){ /*Hacemos AND con 00000010 que en decimal es 2 para ver si el campo SYN esta a 0 o a 1*/
			printf("SYN = 1\n");
		} else {
			printf("SYN = 0\n");
		}
	}
	
	paquetes_filtrados += 1;
}
