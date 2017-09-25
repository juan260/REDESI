/***************************************************************************
<<<<<<< HEAD
 Practica 1
=======
practica1.c
Programa que dependiendo del numero de argumentos de entrada o muestra los 
paquetes capturados con fecha modificada, o muestra los paquetes con una determinada
traza. En ambos casos, el programa muestra el argumento N.

Compila: gcc -Wall -o EjemploPcapNextEx EjemploPcapNextEx.c -lpcap
Autor: Claudia Cea, Juan Riera
>>>>>>> 8ecb5d826a53f496e949c3e79baa9328f33080f0
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
#define MAXBUF 512		// Tamanio maximo de primer argumento


/* Variables globales */

pcap_t *descr=NULL,*descr2=NULL;
pcap_dumper_t *pdumper=NULL;

int contador =0;

/**
*	Funcion para imprimir el paquete que devuelve 1 en caso de error
**/
int imprimir_paquete(uint8_t paquete, int N){
	char buffer[MAXBUF];
	int i;
	if(MAXBUF<N){return 1;}
	sprintf(buffer, "%.512x", paquete);
	if (strlen(buffer)<=2*(N-1)+1){
		//Si el paquete es demasiado corto
		printf("--Error: paquete demasiado corto, mostrando paquete entero.\n");
		for(i=0;i*2<strlen(buffer);i++){
			printf("%c", buffer[2*i]);
			if(i*2+1<strlen(buffer)){
				printf("%c ", buffer[2*i+1]);
			}
		}
	} else {
		for(i=0;i<N;i++){
			printf("%c%c ", buffer[2*i], buffer[2*i+1]);
		}
	}
	printf("\n");
	return 0;
}

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


int main(int argc, char **argv){

	int retorno=0;
	int N;
	char errbuf[PCAP_ERRBUF_SIZE];
	uint8_t *paquete=NULL;
	struct pcap_pkthdr *cabecera=NULL;
	char file_name[256];
	struct timeval time;


    	if(argc<2||argc>3){
       		printf("\n\n\tError al introducir comandos.\n"
		"Instrucciones: \n--Para inciar una captura introducir:\n\n\t"
		"./practia1 N\n\nDonde N será el número de bytes a mostrar\n"
		"de cada paquete.\n\n--Para leer una traza introducir:\n\n\t"
		"./practica1 N name\n\nDonde N será el número de bytes a mostrar\n"
		"de cada paquete y name el nombre de la traza.\n\n");
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
		    printf("Nuevo paquete capturado a las %s\nContenido del paquete: %u\n\n",
		        ctime((const time_t*)&(cabecera->ts.tv_sec)), *paquete);
		        
		    cabecera->ts.tv_sec+=172800;
            	printf("Paquete capturado con fecha editada %s\n",ctime((const time_t*)&(cabecera->ts.tv_sec)));

		
		    if(imprimir_paquete(*paquete, N)){
			    printf("Error, aumentar MAXBUF\n\n");
			    break;
		    }
		
            if(pdumper){

			    pcap_dump((uint8_t *)pdumper,cabecera,paquete);
		    }
	    }
	    pcap_close(descr2);
	    pcap_dump_close(pdumper);
	}   else    {
        	// En caso de que haya dos argumentos
        	descr = pcap_open_offline(argv[2], errbuf);
        	if(descr==NULL){
              		printf("Error: pcap_open_offline(): %s, %s %d.\n",errbuf,__FILE__,__LINE__);
              		exit(ERROR);
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
		        printf("Nuevo paquete capturado a las %s\nContenido del paquete: %u\n\n",
		            ctime((const time_t*)&(cabecera->ts.tv_sec)), *paquete);
		
		        if(imprimir_paquete(*paquete, N)){
			        printf("Error, aumentar MAXBUF\n\n");
			        break;
		        }
	        }
    	}
	pcap_close(descr);
	


	return OK;
}

