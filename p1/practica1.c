/***************************************************************************
 EjemploPcapNext.c
 Muestra el tiempo de llegada de los primeros 500 paquetes a la interface eth0
y los vuelca a traza (¿correctamente?) nueva con tiempo actual

 Compila: gcc -Wall -o EjemploPcapNextEx EjemploPcapNextEx.c -lpcap
 Autor: Jose Luis Garcia Dorado
 2017 EPS-UAM
***************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <signal.h>
#include <time.h>
#define OK 0
#define ERROR 1

#define ETH_FRAME_MAX 1514	// Tamanio maximo trama ethernet
#define MAXBUF 100		// Tamanio maximo de N (primer argumento)

pcap_t *descr=NULL,*descr2=NULL;
pcap_dumper_t *pdumper=NULL;

int contador =0;

void handle(int nsignal){
	printf("\nControl C pulsado\n");
	printf("Paquetes capturados: %d\n", contador);
	if(descr)
		pcap_close(descr);
	if(descr2)
		pcap_close(descr2);
	if(pdumper)
		pcap_dump_close(pdumper);
	exit(OK);
 }

int main(int argc, char **argv)
{

	int retorno=0, N, i;
	char errbuf[PCAP_ERRBUF_SIZE], buffer[MAXBUF];
	uint8_t *paquete=NULL;
	struct pcap_pkthdr *cabecera=NULL;
	char file_name[256];
	struct timeval time;

    if(argc<2){
        printf("COmands.\n");
        exit(EXIT_SUCCESS);

        }
	
	if(signal(SIGINT,handle)==SIG_ERR){
		printf("Error: Fallo al capturar la senal SIGINT.\n");
		exit(ERROR);
	}	

	N=atoi(argv[1]);

    if(argc==2){
		//Apertura de interface
   	if ((descr = pcap_open_live("eth0",9,0,100, errbuf)) == NULL){
		printf("Error: pcap_open_live(): %s, %s %d.\n",errbuf,__FILE__,__LINE__);
		exit(ERROR);
	}
		//Volcado de traza
	descr2=pcap_open_dead(DLT_EN10MB,ETH_FRAME_MAX);
	if (!descr2){
		printf("Error al abrir el dump.\n");
		pcap_close(descr);
		exit(ERROR);
	}
	gettimeofday(&time,NULL);
	sprintf(file_name,"eth0.%lld.pcap",(long long)time.tv_sec);
	pdumper=pcap_dump_open(descr2,file_name);
	if(!pdumper){
		printf("Error al abrir el dumper: %s, %s %d.\n",pcap_geterr(descr2),__FILE__,__LINE__);
		pcap_close(descr);
		pcap_close(descr2);
	}


	while (1){
		retorno = pcap_next_ex(descr,&cabecera,(const u_char **)&paquete);
		if(retorno == -1){ 		//En caso de error
			printf("Error al capturar un paquete %s, %s %d.\n",pcap_geterr(descr),__FILE__,__LINE__);
			pcap_close(descr);
			pcap_close(descr2);
			pcap_dump_close(pdumper);
			exit(ERROR);
		}
		else if(retorno == 0){
			continue;
		}
		else if(retorno==-2){
			break;
		}
			//En otro caso
		contador++;
		printf("Nuevo paquete capturado a las %s\n",ctime((const time_t*)&(cabecera->ts.tv_sec)));
		cabecera->ts.tv_sec+=172800;
        	printf("Nuevo paquete capturado con fecha editada %s\n",ctime((const time_t*)&(cabecera->ts.tv_sec)));
		
		sprintf(buffer, "%x", paquete);
		if (strlen(buffer)<=2*(N-1)+1){
			//Si el paquete es demasiado corto
			printf("--Error: paquete demasiado corto, mostrando paquete entero.\n");
			for(i=0;i*2<strlen(buffer);i++){
				printf("%c", buffer[2*i]);
				if(i*2+1<strlen(buffer)){
					printf("%c ", buffer[2*i+1];
				}
			}
		} else {
			for(i=0;i<N;i++){
				printf("%c%c ", buffer[2*i], buffer[2*i+1]);
			}
		}
		printf("\n");
        if(pdumper){

			pcap_dump((uint8_t *)pdumper,cabecera,paquete);
		}
	}
	pcap_close(descr);
	pcap_close(descr2);
	pcap_dump_close(pdumper);
}
	return OK;
}

