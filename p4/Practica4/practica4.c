/***************************************************************************
 practica4.c
 Inicio, funciones auxiliares y modulos de transmision implmentados y a implementar de la practica 4.
Compila con warning pues falta usar variables y modificar funciones
 
 Compila: make
 Autor: Jose Luis Garcia Dorado
 2014 EPS-UAM v2
***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pcap/pcap.h>
#include <sys/time.h>
#include "interface.h"
#include "practica4.h"

/***************************Variables globales utiles*************************************************/
pcap_t* descr, *descr2; //Descriptores de la interface de red
pcap_dumper_t * pdumper;//y salida a pcap
uint64_t cont=0;	//Contador numero de mensajes enviados
char interface[10];	//Interface donde transmitir por ejemplo "eth0"
uint16_t ID=1;		//Identificador IP
uint16_t sec = 0;

void handleSignal(int nsignal){
	printf("Control C pulsado (%"PRIu64")\n", cont);
	pcap_close(descr);
	exit(OK);
}


uint8_t construirIP(uint8_t *segmento, uint32_t longitud, uint32_t pos_control, uint16_t protocolo_superior, 
            uint8_t *IP_origen, uint8_t *IP_destino, uint16_t protocolo_inferior, uint16_t* pila_protocolos,
            void *parametros);

int main(int argc, char **argv){	

	char errbuf[PCAP_ERRBUF_SIZE];
	char fichero_pcap_destino[CADENAS];
	uint8_t IP_destino_red[IP_ALEN];
	uint16_t MTU;
	uint16_t datalink;
	uint16_t puerto_destino;
	char data[IP_DATAGRAM_MAX];
	uint16_t pila_protocolos[CADENAS];

    ssize_t size=0;
	int long_index=0, file;
	char opt;
	char flag_iface = 0, flag_ip = 0, flag_port = 0, flag_file = 0;

	static struct option options[] = {
		{"if",required_argument,0,'1'},
		{"ip",required_argument,0,'2'},
		{"pd",required_argument,0,'3'},
		{"f",required_argument,0,'4'},
		{"h",no_argument,0,'5'},
		{0,0,0,0}
	};

		//Dos opciones: leer de stdin o de fichero, adicionalmente para pruebas si no se introduce argumento se considera que el mensaje es "Payload "
	while ((opt = getopt_long_only(argc, argv,"1:2:3:4:5", options, &long_index )) != -1) {
		switch (opt) {

			case '1' :

				flag_iface = 1;
					//Por comodidad definimos interface como una variable global
				sprintf(interface,"%s",optarg);
				break;

			case '2' : 

				flag_ip = 1;
					//Leemos la IP a donde transmitir y la almacenamos en orden de red
				if (sscanf(optarg,"%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8"",
				                   &(IP_destino_red[0]),&(IP_destino_red[1]),&(IP_destino_red[2]),&(IP_destino_red[3])) != IP_ALEN){
					printf("Error: Fallo en la lectura IP destino %s\n", optarg);
					exit(ERROR);
				}

				break;

			case '3' :

				flag_port = 1;
					//Leemos el puerto a donde transmitir y la almacenamos en orden de hardware
				puerto_destino=atoi(optarg);
				break;

			case '4' :

				if(strcmp(optarg,"stdin")==0) {
					if (fgets(data, sizeof data, stdin)==NULL) {
						  	printf("Error leyendo desde stdin: %s %s %d.\n",errbuf,__FILE__,__LINE__);
						return ERROR;
					}
					sprintf(fichero_pcap_destino,"%s%s","stdin",".pcap");
				} else {
					sprintf(fichero_pcap_destino,"%s%s",optarg,".pcap");
                    if((file=open(optarg, O_RDONLY))==-1){
                        printf("Error al abrir el fichero\n");
                        return ERROR;
                    }
                    if((size=read(file, data, IP_DATAGRAM_MAX-2))<=0){
                        printf("Error al leer archivo (posiblemente vacio)\n");
                        return ERROR;
                   } else if(size%2==1){
                        sprintf(data, "%s ", data); //Deben de ser pares!!
                   }
                   if(close(file)==-1){
                        printf("Error al cerrar el fichero\n");
                   }
				}
				flag_file = 1;

				break;

			case '5' : printf("Ayuda. Ejecucion: %s -if interface -ip IP -pd Puerto <-f /ruta/fichero_a_transmitir o stdin>: %d\n",argv[0],argc); exit(ERROR);
				break;

			case '?' : printf("Error. Ejecucion: %s -if interface -ip IP -pd Puerto <-f /ruta/fichero_a_transmitir o stdin>: %d\n",argv[0],argc); exit(ERROR);
				break;

			default: printf("Error. Ejecucion: %s -if interface -ip IP -pd Puerto <-f /ruta/fichero_a_transmitir o stdin>: %d\n",argv[0],argc); exit(ERROR);
				break;
        }
    }

	if ((flag_iface == 0) || (flag_ip == 0) || (flag_port == 0)){
		printf("Error. Ejecucion: %s -if interface -ip IP -pd Puerto <-f /ruta/fichero_a_transmitir o stdin>: %d\n",argv[0],argc);
		exit(ERROR);
	} else {
		printf("Interface:\n\t%s\n",interface);
		printf("IP:\n\t%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\n",IP_destino_red[0],IP_destino_red[1],IP_destino_red[2],IP_destino_red[3]);
		printf("Puerto destino:\n\t%"PRIu16"\n",puerto_destino);
	}

	if (flag_file == 0) {
		sprintf(data,"%s","Payload "); //Deben ser pares!
		sprintf(fichero_pcap_destino,"%s%s","debugging",".pcap");
	}

	if(signal(SIGINT,handleSignal)==SIG_ERR){
		printf("Error: Fallo al capturar la senal SIGINT.\n");
		return ERROR;
	}
		//Inicializamos las tablas de protocolos
	if(inicializarPilaEnviar()==ERROR){
      	printf("Error leyendo desde stdin: %s %s %d.\n",errbuf,__FILE__,__LINE__);
		return ERROR;
	}
		//Leemos el tamano maximo de transmision del nivel de enlace
	if(obtenerMTUInterface(interface, &MTU)==ERROR)
		return ERROR;
		//Descriptor de la interface de red donde inyectar trafico
	if ((descr = pcap_open_live(interface,MTU+ETH_HLEN,0, 0, errbuf)) == NULL){
		printf("Error: pcap_open_live(): %s %s %d.\n",errbuf,__FILE__,__LINE__);
		return ERROR;
	}

	datalink=(uint16_t)pcap_datalink(descr); //DLT_EN10MB==Ethernet

		//Descriptor del fichero de salida pcap para debugging
	descr2=pcap_open_dead(datalink,MTU+ETH_HLEN);
	pdumper=pcap_dump_open(descr2,fichero_pcap_destino);

		//Formamos y enviamos el trafico, debe enviarse un unico segmento por llamada a enviar() aunque luego se traduzca en mas de un datagrama
		//Primero un paquete UDP
		//Definimos la pila de protocolos que queremos seguir
	pila_protocolos[0]=UDP_PROTO; pila_protocolos[1]=IP_PROTO; pila_protocolos[2]=ETH_PROTO;
		//Rellenamos los parametros necesario para enviar el paquete a su destinatario y proceso
	Parametros parametros_udp; memcpy(parametros_udp.IP_destino,IP_destino_red,IP_ALEN); parametros_udp.puerto_destino=puerto_destino;
		//Enviamos
	if(enviar((uint8_t*)data,strlen(data),pila_protocolos,&parametros_udp)==ERROR ){
		printf("Error: enviar(): %s %s %d.\n",errbuf,__FILE__,__LINE__);
		return ERROR;
	}
	else	cont++;

	printf("Enviado mensaje %"PRIu64", almacenado en %s\n\n\n", cont,fichero_pcap_destino);

		//Luego, un paquete ICMP en concreto un ping
	pila_protocolos[0]=ICMP_PROTO; pila_protocolos[1]=IP_PROTO; pila_protocolos[2]=0;
	Parametros parametros_icmp; parametros_icmp.tipo=PING_TIPO; parametros_icmp.codigo=PING_CODE; memcpy(parametros_icmp.IP_destino,IP_destino_red,IP_ALEN);
	if(enviar((uint8_t*)"Probando a hacer un ping",strlen("Probando a hacer un ping"),pila_protocolos,&parametros_icmp)==ERROR ){
		printf("Error: enviar(): %s %s %d.\n",errbuf,__FILE__,__LINE__);
		return ERROR;
	}
	else	cont++;
	printf("Enviado mensaje %"PRIu64", ICMP almacenado en %s\n\n", cont,fichero_pcap_destino);

		//Cerramos descriptores
	pcap_close(descr);
	pcap_dump_close(pdumper);
	pcap_close(descr2);
	return OK;
}


/****************************************************************************************
* Nombre: enviar 									*
* Descripcion: Esta funcion envia un mensaje						*
* Argumentos: 										*
*  -mensaje: mensaje a enviar								*
*  -pila_protocolos: conjunto de protocolos a seguir					*
*  -longitud: bytes que componen mensaje						*
*  -parametros: parametros necesario para el envio (struct parametros)			*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t enviar(uint8_t* mensaje, uint64_t longitud,uint16_t* pila_protocolos,void *parametros){
	uint16_t protocolo=pila_protocolos[0];
	printf("Enviar(%"PRIu16") %s %d.\n",protocolo,__FILE__,__LINE__);
	if(protocolos_registrados[protocolo]==NULL){
		printf("Protocolo %"PRIu16" desconocido\n",protocolo);
		return ERROR;
	}
	else {
		return protocolos_registrados[protocolo](mensaje,longitud,pila_protocolos,parametros);
	}
	return ERROR;
}




/****************************************************************************************
* Nombre: moduloUDP 									*
* Descripcion: Esta funcion implementa el modulo de envio UDP				*
* Argumentos: 										*
*  -mensaje: mensaje a enviar								*
*  -pila_protocolos: conjunto de protocolos a seguir					*
*  -longitud: bytes que componen mensaje						*
*  -parametros: parametros necesario para el envio este protocolo			*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t moduloUDP(uint8_t* mensaje,uint64_t longitud, uint16_t* pila_protocolos,void *parametros){
	uint8_t segmento[UDP_SEG_MAX]={0};
	uint16_t puerto_origen = 0;
	uint16_t aux16;
	uint32_t pos=0;
	uint16_t protocolo_inferior=pila_protocolos[1];
	printf("modulo UDP(%"PRIu16") %s %d.\n",protocolo_inferior,__FILE__,__LINE__);

	if (longitud>(pow(2,16)-UDP_HLEN)){
		printf("Error: mensaje demasiado grande para UDP (%f).\n",(pow(2,16)-UDP_HLEN));
		return ERROR;
	}

	Parametros udpdatos=*((Parametros*)parametros);
	uint16_t puerto_destino=udpdatos.puerto_destino;

    	if(obtenerPuertoOrigen(&puerto_origen)==ERROR){
        	printf("Error al obtener el puerto origen UDP");
        	return ERROR;
    	}
	
	/*Puerto origen*/
	aux16=htons(puerto_origen);
	memcpy(segmento+pos,&aux16,sizeof(uint16_t));
	pos+=sizeof(uint16_t);

	/*Puerto destino*/
	aux16=htons(puerto_destino);
    	memcpy(segmento+pos,&aux16,sizeof(uint16_t));
    	pos+=sizeof(uint16_t);

	/*Longitud*/
    	uint16_t longitudUDP=longitud+UDP_PROTO;
    	aux16=htons(longitudUDP);
    	memcpy(segmento+pos,&aux16,sizeof(uint16_t));
    	pos+=sizeof(uint16_t);

	/*Suma de control*/
    	aux16=(uint16_t)0;
    	memcpy(segmento+pos,&aux16,sizeof(uint16_t));
    	pos+=sizeof(uint16_t);

	/*Octetos de datos*/
    	memcpy(segmento+pos,mensaje,longitud);

	//Se llama al protocolo definido de nivel inferior a traves de los punteros registrados en la tabla de protocolos registrados
	return protocolos_registrados[protocolo_inferior](segmento,longitud+pos,pila_protocolos,parametros);
}


/****************************************************************************************
* Nombre: moduloIP 									*
* Descripcion: Esta funcion implementa el modulo de envio IP				*
* Argumentos: 										*
*  -segmento: segmento a enviar								*
*  -pila_protocolos: conjunto de protocolos a seguir					*
*  -longitud: bytes que componen el segmento						*
*  -parametros: parametros necesario para el envio este protocolo			*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t moduloIP(uint8_t* segmento, uint64_t longitud, uint16_t* pila_protocolos,void *parametros){
    uint16_t MTU;
    int i;
	uint32_t pos_control=0;
	uint8_t IP_origen[IP_ALEN];
	uint16_t protocolo_superior=pila_protocolos[0];
	uint16_t protocolo_inferior=pila_protocolos[2];
    uint16_t fragSize=0;
	pila_protocolos++;
	uint8_t mascara[IP_ALEN],IP_rango_origen[IP_ALEN],IP_rango_destino[IP_ALEN],gateway[IP_ALEN];

    	printf("modulo IP(%"PRIu16") %s %d.\n",protocolo_inferior,__FILE__,__LINE__);

	Parametros ipdatos=*((Parametros*)parametros);
	uint8_t* IP_destino=ipdatos.IP_destino;
    	if(obtenerIPInterface(interface, IP_origen)==ERROR){
        	printf("Error al obtener la ip de origen\n");
        	return ERROR;
    	}
    
    	if(obtenerMascaraInterface(interface, mascara)==ERROR){
        	printf("Error al obtener la mascara\n");
        	return ERROR;
    	}

    	if(aplicarMascara(IP_origen, mascara, IP_ALEN, IP_rango_origen) == ERROR){
        	printf("Error al aplicar la mascara de destino\n");
        	return ERROR;
    	}
        
    	if(aplicarMascara(IP_destino, mascara, IP_ALEN, IP_rango_destino) == ERROR){
        	printf("Error al aplicar la mascara de destino\n");
        	return ERROR;
    	}
    
    
    	if(IP_rango_destino==IP_rango_origen){
        	/* Esta en la misma red local */
        	if(ARPrequest(interface, IP_destino,(ipdatos.ETH_destino))==ERROR){
            		printf("Error al hacer ARPrequest\n");
            		return ERROR;
        	}
    	} else {
        	/* Esta en distinta red local, usar gateway */
        	if(obtenerGateway(interface, gateway)==ERROR){
            		printf("Error al obtener gateway\n");
            		return ERROR;
        	}

        	if(ARPrequest(interface, gateway,(ipdatos.ETH_destino))==ERROR){
            		printf("Error al hacer ARPrequest al gateway\n");
            		return ERROR;
        	}
    	}
    
    	if(longitud>IP_DATAGRAM_MAX){
        	printf("Error: paquete demasiado grande para IP\n");
        	return ERROR;
    	}

    	if(obtenerMTUInterface(interface, &MTU)==ERROR){
        	printf("Error al obtener MTU\n");
        	return ERROR;
    	}

	//Hacemos MTU multiplode 8 paraque sea expresable con pos
    	fragSize=((MTU-IP_HEAD_LEN)/8)*8;
    	//TODO 
        printf("\nfragSize, MTU, IP_HEAD_LEN, %d, %d, %d, longitud, %d\n\n", (int)fragSize, (int)MTU, (int)IP_HEAD_LEN, (int)longitud);
        for(i=0;i<longitud/fragSize;i++){
            printf("BUCLEEEEEi\n");        
        	if(construirIP(segmento+pos_control, fragSize, pos_control, protocolo_superior, 
            		IP_origen, IP_destino, protocolo_inferior, pila_protocolos, &ipdatos)==ERROR){
            		printf("Error al construir el paquete IP\n");
            		return ERROR;
        	}
        	pos_control+=fragSize;
    	}

    	if(construirIP(segmento+pos_control, longitud%fragSize, pos_control, protocolo_superior, 
        IP_origen, IP_destino, protocolo_inferior, pila_protocolos, &ipdatos)==ERROR){
        	printf("Error al construir el paquete IP\n");
        	return ERROR;
    	}

    	return OK;
}

/*****************************************************************************************
* Nombre: construirIP 									 *
* Descripcion: Esta funcion implementa la construccion y el envio en si de cada fragmento*
* Argumentos: 										 *
*  -segmento: segmento a enviar							         *
*  -longitud: longitud del fragmento a enviar					         *
*  -pos_control: cantidad de datagrama ya enviado (por fragmentos anteriores)		 *
*  -protocolo_superior: protocolo superior a IP			                         *
*  -IP_origen: ip de origen (no en orden de red)                                         *
*  -IP_destino: ip destino (no en orden de red)                                          *
*  -protocolo_inferior: procolo inferior al actual, al que se ve a enviar el paquete     *
*  -pila_protocolos-parametros: como en la funcion superior                              *
*  Retorno: OK/ERROR									 *
*****************************************************************************************/
uint8_t construirIP(uint8_t *segmento, uint32_t longitud, uint32_t pos_control, uint16_t protocolo_superior, 
            uint8_t * IP_origen, uint8_t * IP_destino, uint16_t protocolo_inferior, uint16_t* pila_protocolos,
            void *parametros){
        uint8_t aux8, checksum[2];
        uint16_t aux16;
        uint32_t pos=0, checksumPos=0;
	    uint8_t datagrama[IP_DATAGRAM_MAX]={0};
        int i;
    
	/*Version 4, IHL 5*/
        aux8=69;
        memcpy(datagrama+pos,&aux8,sizeof(uint8_t));
        pos+=sizeof(uint8_t);

	/*Tipo de servicio*/
        aux8=0;
        memcpy(datagrama+pos,&aux8,sizeof(uint8_t));
        pos+=sizeof(uint8_t);

	/*Longitud total*/
        aux16=htons(longitud+IP_HEAD_LEN);
        memcpy(datagrama+pos,&aux16,sizeof(uint16_t));
        pos+=sizeof(uint16_t);
        
	/*Identificacion*/
        aux16=htons(ID);
        memcpy(datagrama+pos,&aux16,sizeof(uint16_t));
        ID++;
        pos+=sizeof(uint16_t);
        
	/*Flags, posicion*/
        aux16=htons(8192+(pos_control/8)); 
        memcpy(datagrama+pos,&aux16,sizeof(uint16_t));
        pos+=sizeof(uint16_t);

	/*Tiempo de vida*/
        aux8=128; 
        memcpy(datagrama+pos,&aux8,sizeof(uint8_t));
        pos+=sizeof(uint8_t);


        aux8=(protocolo_superior);
        memcpy(datagrama+pos,&(aux8),sizeof(uint8_t));
        pos+=sizeof(uint8_t);
    
        /*Guardamos la posicion del checksum para calcularlo y almacenarlo despues*/
        checksumPos=pos;
        aux16=htons(0);
        memcpy(datagrama+pos,&aux16,sizeof(uint16_t));
        pos+=sizeof(uint8_t);

	/*IP origen*/
        for(i=0;i<IP_ALEN;i++){
            memcpy(datagrama+pos,IP_origen+i,sizeof(uint8_t));
            pos+=sizeof(uint8_t);

        }
	/*IP destino*/

        for(i=0;i<IP_ALEN;i++){
            memcpy(datagrama+pos,IP_destino+i,sizeof(uint8_t));
            pos+=sizeof(uint8_t);

        }

        /*Cabecera completa, calculamos checksum, que nos viene dado en orden de red*/
        calcularChecksum(IP_HEAD_LEN, datagrama, checksum);
        memcpy(datagrama+checksumPos,checksum,sizeof(uint16_t));

        /*Por úlimo añadimos el mensaje*/
        memcpy(datagrama+pos,segmento,longitud);

            mostrarPaquete(datagrama, longitud+IP_HEAD_LEN);
printf("\n");
	return protocolos_registrados[protocolo_inferior](datagrama,longitud+IP_HEAD_LEN,pila_protocolos,parametros);
}


/****************************************************************************************
* Nombre: moduloETH 									*
* Descripcion: Esta funcion implementa el modulo de envio Ethernet			*
* Argumentos: 										*
*  -datagrama: datagrama a enviar							*
*  -pila_protocolos: conjunto de protocolos a seguir					*
*  -longitud: bytes que componen el datagrama						*
*  -parametros: Parametros necesario para el envio este protocolo			*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t moduloETH(uint8_t* datagrama, uint64_t longitud, uint16_t* pila_protocolos,void *parametros){
	uint8_t aux8;
	uint8_t pos=0;
	uint8_t ETH_origen[ETH_ALEN];
	uint8_t trama[ETH_FRAME_MAX];
	uint16_t aux16;
    	uint16_t protocolo_superior=pila_protocolos[0];
	int i;
    struct pcap_pkthdr pkt_header[1];
    struct timeval time;
    pila_protocolos++;

	Parametros ipdatos=*((Parametros*)parametros);
	uint8_t* ETH_destino=ipdatos.ETH_destino;

	printf("modulo ETH(fisica) %s %d.\n",__FILE__,__LINE__);	
    printf("\nLongitud: %d\n\n", (int)longitud);
	if(longitud>ETH_FRAME_MAX){
        	printf("Error: paquete demasiado grande para Ethernet\n");
        	return ERROR;
    	}

	if(obtenerMACdeInterface(interface, ETH_origen)==ERROR){
        	printf("Error al obtener la dirección MAC de origen\n");
        	return ERROR;
    	}

	/*Direccion ETH destino*/	
	for(i=0;i<ETH_ALEN;i++){
		aux8 = ETH_destino[i];
		printf("\nETHDESTINO[i]=%d", (int)aux8);
        	memcpy(trama+pos,&aux8,sizeof(uint8_t));
        	pos+=sizeof(uint8_t);	
	}

	/*Direccion ETH origen*/
	for(i=0;i<ETH_ALEN;i++){
		aux8 = ETH_origen[i];
        	memcpy(trama+pos,&aux8,sizeof(uint8_t));
        	pos+=sizeof(uint8_t);	
	}

	/*Tipo Ethernet*/
	aux16=htons(protocolo_superior);
    memcpy(trama+pos,&aux16,sizeof(uint16_t));
    pos+=sizeof(uint16_t);
	
	/*Por úlimo añadimos el mensaje*/
        memcpy(trama+pos,datagrama,longitud+ETH_HLEN);

	//Enviar a capa fisica [...]
    if(pcap_sendpacket(descr,(u_char *)trama, longitud+ETH_HLEN)!=0){
		return ERROR;
	}
    printf("Paquete enviado correctamente\n");
       mostrarPaquete(trama, longitud+ETH_HLEN);
printf("\n");
	
    gettimeofday(&time, NULL);
    pkt_header->ts.tv_sec=time.tv_sec;
    pkt_header->ts.tv_usec=time.tv_usec;
    pkt_header->len=longitud+ETH_HLEN;
    pkt_header->caplen=longitud+ETH_HLEN;

    pcap_dump((uint8_t *)pdumper,pkt_header,(u_char *)trama);

	return OK;

}


/****************************************************************************************
* Nombre: moduloICMP 									*
* Descripcion: Esta funcion implementa el modulo de envio ICMP				*
* Argumentos: 										*
*  -mensaje: mensaje a anadir a la cabecera ICMP					*
*  -pila_protocolos: conjunto de protocolos a seguir					*
*  -longitud: bytes que componen el mensaje						*
*  -parametros: parametros necesario para el envio este protocolo			*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t moduloICMP(uint8_t* mensaje,uint64_t longitud, uint16_t* pila_protocolos,void *parametros){
	uint8_t aux8, checksum[2];
	uint16_t aux16, pos=0, checksumPos;
	uint8_t datagrama[ICMP_DATAGRAM_MAX]={0};
	uint16_t protocolo_inferior=pila_protocolos[2];
	uint8_t IP_origen[IP_ALEN];
	uint8_t gateway[IP_ALEN];
	uint8_t mascara[IP_ALEN];
	uint8_t IP_rango_origen[IP_ALEN];
	uint8_t IP_rango_destino[IP_ALEN];
	pila_protocolos++;

    
    printf("modulo ICMP %s %d.\n",__FILE__,__LINE__);

	if(longitud>ICMP_DATAGRAM_MAX){
        	printf("Error: paquete demasiado grande para ICMP\n");
        	return ERROR;
    	}
	
	Parametros ipdatos=*((Parametros*)parametros);
	uint8_t* IP_destino=ipdatos.IP_destino;
    	if(obtenerIPInterface(interface, IP_origen)==ERROR){
        	printf("Error al obtener la ip de origen\n");
        	return ERROR;
    	}
    
    	if(obtenerMascaraInterface(interface, mascara)==ERROR){
        	printf("Error al obtener la mascara\n");
        	return ERROR;
    	}

    	if(aplicarMascara(IP_origen, mascara, IP_ALEN, IP_rango_origen) == ERROR){
        	printf("Error al aplicar la mascara de destino\n");
        	return ERROR;
    	}
        
    	if(aplicarMascara(IP_destino, mascara, IP_ALEN, IP_rango_destino) == ERROR){
        	printf("Error al aplicar la mascara de destino\n");
        	return ERROR;
    	}
    
    
    	if(IP_rango_destino==IP_rango_origen){
        	/* Esta en la misma red local */
        	if(ARPrequest(interface, IP_destino,(ipdatos.ETH_destino))==ERROR){
            		printf("Error al hacer ARPrequest\n");
            		return ERROR;
        	}
    	} else {
        	/* Esta en distinta red local, usar gateway */
        	if(obtenerGateway(interface, gateway)==ERROR){
            		printf("Error al obtener gateway\n");
            		return ERROR;
        	}

        	if(ARPrequest(interface, gateway,(ipdatos.ETH_destino))==ERROR){
            		printf("Error al hacer ARPrequest al gateway\n");
            		return ERROR;
        	}
    	}

	/*Tipo*/	
	aux8 = 8;
	memcpy(datagrama+pos,&aux8,sizeof(uint8_t));
    pos+=sizeof(uint8_t);

	/*Codigo*/	
	aux8 = 0;
	memcpy(datagrama+pos,&aux8,sizeof(uint8_t));
    pos+=sizeof(uint8_t);

	/*Suma de control*/
	checksumPos=pos;
    aux16=htons(0);
    memcpy(datagrama+pos,&aux16,sizeof(uint16_t));
	pos+=sizeof(uint16_t);

	/*Identificador*/
	aux16=htons(0);
	memcpy(datagrama+pos,&aux16,sizeof(uint16_t));
	pos+=sizeof(uint16_t);

	/*Numero de secuencia*/
	aux16=htons(sec);
        memcpy(datagrama+pos,&aux16,sizeof(uint16_t));
	pos+=sizeof(uint16_t);
    sec++;
    
	/*Datos*/
	memcpy(datagrama+pos,mensaje,longitud);

	/*Cabecera completa, calculamos checksum, que nos viene dado en orden de red*/
        calcularChecksum(ICMP_HLEN+longitud, datagrama, checksum);
        memcpy(datagrama+checksumPos,checksum,sizeof(uint16_t));

	return protocolos_registrados[protocolo_inferior](datagrama,longitud+ICMP_HLEN,pila_protocolos,&ipdatos);

}


/***************************Funciones auxiliares a implementar***********************************/

/****************************************************************************************
* Nombre: aplicarMascara 								*
* Descripcion: Esta funcion aplica una mascara a una vector				*
* Argumentos: 										*
*  -IP: IP a la que aplicar la mascara en orden de red					*
*  -mascara: mascara a aplicar en orden de red						*
*  -longitud: bytes que componen la direccion (IPv4 == 4)				*
*  -resultado: Resultados de aplicar mascara en IP en orden red				*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t aplicarMascara(uint8_t* IP, uint8_t* mascara, uint32_t longitud, uint8_t* resultado){
    int i;
    for(i=0;i<longitud;i++){
        resultado[i]=IP[i]&mascara[i];
    }
    return OK;
}


/***************************Funciones auxiliares implementadas**************************************/

/****************************************************************************************
* Nombre: mostrarPaquete 								*
* Descripcion: Esta funcion imprime por pantalla en hexadecimal un vector		*
* Argumentos: 										*
*  -paquete: bytes que conforman un paquete						*
*  -longitud: Bytes que componen el mensaje						*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t mostrarPaquete(uint8_t * paquete, uint32_t longitud){
	uint32_t i;
	printf("Paquete:\n");
	for (i=0;i<longitud;i++){
		printf("%02"PRIx8" ", paquete[i]);
	}
	printf("\n");
	return OK;
}


/****************************************************************************************
* Nombre: calcularChecksum							     	*
* Descripcion: Esta funcion devuelve el ckecksum tal como lo calcula IP/ICMP		*
* Argumentos:										*
*   -longitud: numero de bytes de los datos sobre los que calcular el checksum		*
*   -datos: datos sobre los que calcular el checksum					*
*   -checksum: checksum de los datos (2 bytes) en orden de red! 			*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t calcularChecksum(uint16_t longitud, uint8_t *datos, uint8_t *checksum) {
    uint16_t word16;
    uint32_t sum=0;
    int i;
    // make 16 bit words out of every two adjacent 8 bit words in the packet
    // and add them up
    for (i=0; i<longitud; i=i+2){
        word16 = (datos[i]<<8) + datos[i+1];
        sum += (uint32_t)word16;       
    }
    // take only 16 bits out of the 32 bit sum and add up the carries
    while (sum>>16) {
        sum = (sum & 0xFFFF)+(sum >> 16);
    }
    // one's complement the result
    sum = ~sum;      
    checksum[0] = sum >> 8;
    checksum[1] = sum & 0xFF;
    return OK;
}


/***************************Funciones inicializacion implementadas*********************************/

/****************************************************************************************
* Nombre: inicializarPilaEnviar     							*
* Descripcion: inicializar la pila de red para enviar registrando los distintos modulos *
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t inicializarPilaEnviar() {
	bzero(protocolos_registrados,MAX_PROTOCOL*sizeof(pf_notificacion));
	if(registrarProtocolo(ETH_PROTO, moduloETH, protocolos_registrados)==ERROR)
		return ERROR;
	if(registrarProtocolo(IP_PROTO, moduloIP, protocolos_registrados)==ERROR)
		return ERROR;
	if(registrarProtocolo(UDP_PROTO, moduloUDP, protocolos_registrados)==ERROR)
		return ERROR;
	if(registrarProtocolo(ICMP_PROTO, moduloICMP, protocolos_registrados)==ERROR)
		return ERROR; 

	return OK;
}


/****************************************************************************************
* Nombre: registrarProtocolo 								*
* Descripcion: Registra un protocolo en la tabla de protocolos 				*
* Argumentos:										*
*  -protocolo: Referencia del protocolo (ver RFC 1700)					*
*  -handleModule: Funcion a llamar con los datos a enviar				*
*  -protocolos_registrados: vector de funciones registradas 				*
* Retorno: OK/ERROR 									*
*****************************************************************************************/

uint8_t registrarProtocolo(uint16_t protocolo, pf_notificacion handleModule, pf_notificacion* protocolos_registrados){
	if(protocolos_registrados==NULL ||  handleModule==NULL){		
		printf("Error: registrarProtocolo(): entradas nulas.\n");
		return ERROR;
	}
	else
		protocolos_registrados[protocolo]=handleModule;
	return OK;
}


