#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <pcap.h>
#include <signal.h>
#include <semaphore.h>
#include <getopt.h>
#include <pthread.h>
#include "ProbeMon.h"

#define MAX_RECORDS 3
#define ETH_ALEN 6
struct station_info {
    int8_t mac_addr[20];
    char mac[20];
    char hint[255];
};

struct station_info stations[3];

CIRCLEQ_HEAD(circleq, entry) rx_head;
CIRCLEQ_HEAD(circleq_disp, entry) display_head;
char *csv_file = NULL;
char *mode = NULL;
struct circleq *head_rx;
struct circleq_disp *head_dsip;
pthread_mutex_t disp_lock;
sem_t tx_sem;
char server_ip[255];
char client_ip[255];
pthread_t disp_thread;
pcap_t *handle;
int isClosing;
enum cap_mode capture_mode;

void TermHandler(int sig)
{
	isClosing = 1;
	pcap_breakloop(handle);
	sem_post(&tx_sem);
}

//that's a rip
const char* getfield(char* line, int num)
{
    const char* tok;
    for (tok = strtok(line, ",");
            tok && *tok;
            tok = strtok(NULL, ",\n"))
    {
        if (!--num)
            return tok;
    }
    return NULL;
}

void parse_csv_file(char* csv_file)
{
    struct station_info stations[3];
    int count = 0;
    char line[275];
    FILE* mac_file = fopen(csv_file, "r");
    if(mac_file == NULL)
    {
    	printf("Can't open csv file\n");
    	exit(1);
    }

    while (fgets(line, 275, mac_file))
    {
        char* tmp = strdup(line);
        sprintf(&stations[count].mac[0],"%s", getfield(tmp, 1));
        tmp = strdup(line);
        sprintf(&stations[count].hint[0],"%s",getfield(tmp, 2));
        free(tmp);
        sscanf(&stations[count].mac[0], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &stations[count].mac_addr[0], &stations[count].mac_addr[1],\
        		&stations[count].mac_addr[2], &stations[count].mac_addr[3], &stations[count].mac_addr[4], &stations[count].mac_addr[5]);
        count++;
        if(count >= MAX_RECORDS){
            break;
        }
    }
    fclose(mac_file);
    printf("MAC-%s ", stations[0].mac);
    printf("Hint-%s\n", stations[0].hint);
    printf("MAC-%s ", stations[1].mac);
    printf("Hint-%s\n", stations[1].hint);
    printf("MAC-%s ", stations[2].mac);
    printf("Hint-%s\n", stations[2].hint);

}

void frame_ready(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	struct entry *e;
	e = malloc(sizeof (struct entry));
    e->packet_size = pkthdr->len;
	e->packet = (u_char*)packet;
	pthread_mutex_lock(&disp_lock);
	CIRCLEQ_INSERT_HEAD(&rx_head, e, entries);
	pthread_mutex_unlock(&disp_lock);
	sem_post(&tx_sem);

}

void get_frame_types(uint16_t frame_ctl, struct frame_types_desc *ftd)
{
	uint32_t frame_type = 0;
	uint32_t frame_type_mask = 12;
	uint32_t frame_sub_type = 0;
	uint32_t frame_sub_type_mask = 240;

	frame_type = frame_ctl & frame_type_mask;
	frame_sub_type = frame_ctl & frame_sub_type_mask;

	ftd->frame_type = frame_type;
	ftd->frame_sub_type = frame_sub_type;
}
void get_mgmt_subtype(char* sub_type_string, uint32_t sub_type)
{
	switch(sub_type)
	{
		case RTW_IEEE80211_STYPE_ASSOC_REQ:
			strcpy(sub_type_string, "STYPE_ASSOC_REQ");
			break;
		case RTW_IEEE80211_STYPE_ASSOC_RESP:
			strcpy(sub_type_string, "STYPE_ASSOC_RESP");
			break;
		case RTW_IEEE80211_STYPE_REASSOC_REQ:
			strcpy(sub_type_string, "STYPE_REASSOC_REQ");
			break;
		case RTW_IEEE80211_STYPE_REASSOC_RESP:
			strcpy(sub_type_string, "STYPE_REASSOC_RESP");
			break;
		case RTW_IEEE80211_STYPE_PROBE_REQ:
			strcpy(sub_type_string, "STYPE_PROBE_REQ");
			break;
		case RTW_IEEE80211_STYPE_PROBE_RESP:
			strcpy(sub_type_string, "STYPE_PROBE_RESP");
			break;
		case RTW_IEEE80211_STYPE_BEACON:
			strcpy(sub_type_string, "STYPE_BEACON");
			break;
		case RTW_IEEE80211_STYPE_ATIM:
			strcpy(sub_type_string, "STYPE_ATIM");
			break;
		case RTW_IEEE80211_STYPE_DISASSOC:
			strcpy(sub_type_string, "STYPE_DISASSOC");
			break;
		case RTW_IEEE80211_STYPE_AUTH:
			strcpy(sub_type_string, "STYPE_AUTH");
			break;
		case RTW_IEEE80211_STYPE_DEAUTH:
			strcpy(sub_type_string, "STYPE_DEAUTH");
			break;
		case RTW_IEEE80211_STYPE_ACTION:
			strcpy(sub_type_string, "STYPE_ACTION");
			break;
		default:
			strcpy(sub_type_string, "UNKNOWN FRAME SUB TYPE");
			break;
	}
}
void get_ctl_subtype(char* sub_type_string, uint32_t sub_type)
{
	switch(sub_type)
	{
		case RTW_IEEE80211_STYPE_CTL_EXT:
			strcpy(sub_type_string, "STYPE_CTL_EXT");
			break;
		case RTW_IEEE80211_STYPE_BACK_REQ:
			strcpy(sub_type_string, "STYPE_BACK_REQ");
			break;
		case RTW_IEEE80211_STYPE_BACK:
			strcpy(sub_type_string, "STYPE_BACK");
			break;
		case RTW_IEEE80211_STYPE_PSPOLL:
			strcpy(sub_type_string, "STYPE_PSPOLL");
			break;
		case RTW_IEEE80211_STYPE_RTS:
			strcpy(sub_type_string, "STYPE_RTS");
			break;
		case RTW_IEEE80211_STYPE_CTS:
			strcpy(sub_type_string, "STYPE_CTS");
			break;
		case RTW_IEEE80211_STYPE_ACK:
			strcpy(sub_type_string, "STYPE_ACK");
			break;
		case RTW_IEEE80211_STYPE_CFEND:
			strcpy(sub_type_string, "STYPE_CFEND");
			break;
		case RTW_IEEE80211_STYPE_CFENDACK:
			strcpy(sub_type_string, "STYPE_CFENDACK");
			break;
		default:
			strcpy(sub_type_string, "UNKNOWN FRAME SUB TYPE");
			break;
	}
}
void get_data_subtype(char* sub_type_string, uint32_t sub_type)
{
	switch(sub_type)
	{
		case RTW_IEEE80211_STYPE_DATA:
			strcpy(sub_type_string, "STYPE_DATA");
			break;
		case RTW_IEEE80211_STYPE_DATA_CFACK:
			strcpy(sub_type_string, "STYPE_DATA_CFACK");
			break;
		case RTW_IEEE80211_STYPE_DATA_CFPOLL:
			strcpy(sub_type_string, "STYPE_DATA_CFPOLL");
			break;
		case RTW_IEEE80211_STYPE_DATA_CFACKPOLL:
			strcpy(sub_type_string, "STYPE_DATA_CFACKPOLL");
			break;
		case RTW_IEEE80211_STYPE_NULLFUNC:
			strcpy(sub_type_string, "STYPE_NULLFUNC");
			break;
		case RTW_IEEE80211_STYPE_CFACK:
			strcpy(sub_type_string, "STYPE_CFACK");
			break;
		case RTW_IEEE80211_STYPE_CFPOLL:
			strcpy(sub_type_string, "STYPE_CFPOLL");
			break;
		case RTW_IEEE80211_STYPE_CFACKPOLL:
			strcpy(sub_type_string, "STYPE_CFACKPOLL");
			break;
		case RTW_IEEE80211_STYPE_QOS_DATA:
			strcpy(sub_type_string, "STYPE_QOS_DATA");
			break;
		case RTW_IEEE80211_STYPE_QOS_DATA_CFACK:
			strcpy(sub_type_string, "STYPE_QOS_DATA_CFACK");
			break;
		case RTW_IEEE80211_STYPE_QOS_DATA_CFPOLL:
			strcpy(sub_type_string, "STYPE_QOS_DATA_CFPOLL");
			break;
		case RTW_IEEE80211_STYPE_QOS_DATA_CFACKPOLL:
			strcpy(sub_type_string, "STYPE_QOS_DATA_CFACKPOLL");
			break;
		case RTW_IEEE80211_STYPE_QOS_NULLFUNC:
			strcpy(sub_type_string, "STYPE_QOS_NULLFUNC");
			break;
		case RTW_IEEE80211_STYPE_QOS_CFACK:
			strcpy(sub_type_string, "STYPE_QOS_CFACK");
			break;
		case RTW_IEEE80211_STYPE_QOS_CFPOLL:
			strcpy(sub_type_string, "STYPE_QOS_CFPOLL");
			break;
		case RTW_IEEE80211_STYPE_QOS_CFACKPOLL:
			strcpy(sub_type_string, "STYPE_QOS_CFACKPOLL");
			break;
		default:
			strcpy(sub_type_string, "UNKNOWN FRAME SUB TYPE");
			break;
	}
}
void get_ext_subtype(char* sub_type_string, uint32_t sub_type)
{
	strcpy(sub_type_string, "UNKNOWN FRAME SUB TYPE");
}
void* do_print(void *arg)
{
 	struct ieee80211_radiotap_header* radio_header;
 	struct ieee80211_hdr *pmgmnt_hdr;
 	int is_not_equal = 0;
 	int counter = 0;
 	char str[19];
 	char ftype_as_string[255];
 	char fsubtype_as_string[255];
 	struct frame_types_desc ftype;
    struct entry *src;
    struct entry *dest;
    struct entry *disp;
    int print_frame = 0;
    int8_t ssid_len = 0;
    char ssid[255];
    void *max_len;
    int8_t *ssid_ptr;
    int8_t *rssi_ptr;
    int8_t rssi = 0;

    while(isClosing < 1)
    {


        sem_wait(&tx_sem);
        if(isClosing > 0) { return (void*) NULL;}

   	    pthread_mutex_lock(&disp_lock);
   	    while (!CIRCLEQ_EMPTY(&rx_head))
        {
   	    	src = CIRCLEQ_FIRST(&rx_head);
        	dest = malloc(sizeof (struct entry));
        	dest->packet = src->packet;
        	dest->packet_size = src->packet_size;
        	CIRCLEQ_INSERT_HEAD(&display_head, dest, entries);
        	CIRCLEQ_REMOVE(&rx_head, src, entries);
        	free(src);
        }
        pthread_mutex_unlock(&disp_lock);

        while (!CIRCLEQ_EMPTY(&display_head))
        {
        	ssid_len = 0;
        	disp = CIRCLEQ_FIRST(&display_head);
        	radio_header = (struct ieee80211_radiotap_header*)(disp->packet);
        	pmgmnt_hdr = (struct ieee80211_hdr*)(disp->packet + radio_header->it_len);

        	get_frame_types(pmgmnt_hdr->frame_control, &ftype);
        	max_len = radio_header + radio_header->it_len;
        	rssi_ptr = (int8_t*) radio_header + RSSI_OFFSET;
        	if((void*)rssi_ptr <= max_len)
        	{
        		rssi = *rssi_ptr;
        	}
        	switch(ftype.frame_type)
        	{
        		case RTW_IEEE80211_FTYPE_MGMT:
        			strcpy(ftype_as_string, "FTYPE_MGMT");
        			get_mgmt_subtype(&fsubtype_as_string[0], ftype.frame_sub_type);
        			break;
        		case RTW_IEEE80211_FTYPE_CTL:
        			strcpy(ftype_as_string, "FTYPE_CTL");
        			get_ctl_subtype(&fsubtype_as_string[0], ftype.frame_sub_type);
        			break;
        		case RTW_IEEE80211_FTYPE_DATA:
        			strcpy(ftype_as_string, "FTYPE_DATA");
        			get_data_subtype(&fsubtype_as_string[0], ftype.frame_sub_type);
        			break;
        		case RTW_IEEE80211_FTYPE_EXT:
        			strcpy(ftype_as_string, "FTYPE_EXT");
        			get_ext_subtype(&fsubtype_as_string[0], ftype.frame_sub_type);
        			break;
        		default:
        			strcpy(ftype_as_string, "UNKNOWN FRAME TYPE");
        			strcpy(fsubtype_as_string, "UNKNOWN FRAME SUB TYPE");
        			break;
        	}

        	if(capture_mode == all) { print_frame++;}
        	if((capture_mode == probes) || (capture_mode == all))
        	{
				if(ftype.frame_type == RTW_IEEE80211_FTYPE_MGMT)
				{
					if(ftype.frame_sub_type == RTW_IEEE80211_STYPE_PROBE_REQ)
					{
						ssid_ptr = (int8_t*) pmgmnt_hdr;
						ssid_ptr += SSID_OFFSET;
				        ssid_len = *ssid_ptr++;
				        for(counter = 0 ; counter < ssid_len ; counter++)
				        {
				        	ssid[counter] = *ssid_ptr++;
				        }
				        ssid[counter] = 0;
						print_frame++;
					}
					if(ftype.frame_sub_type == RTW_IEEE80211_STYPE_PROBE_RESP)
					{
						print_frame++;
					}
				}
        	}
        	if(capture_mode == cts)
            {
        		if(ftype.frame_type == RTW_IEEE80211_FTYPE_CTL)
            	{
					if(ftype.frame_sub_type == RTW_IEEE80211_STYPE_CTS)
					{
						for(counter = 0 ; counter < MAX_RECORDS ; counter++)
		        	    {
							is_not_equal = memcmp(&stations[counter].mac_addr[0], pmgmnt_hdr->addr1, (sizeof(uint8_t) * ETH_ALEN) );
							if(is_not_equal == 0)
							{
								print_frame++;
							}
		        	    }
					}
            	}
            }

        	if(print_frame > 0)
        	{
				printf("%s    %s    ",ftype_as_string, fsubtype_as_string);
				snprintf(str, sizeof(str), "%02x:%02x:%02x:%02x:%02x:%02x",pmgmnt_hdr->addr2[0],
				  pmgmnt_hdr->addr2[1], pmgmnt_hdr->addr2[2], pmgmnt_hdr->addr2[3], pmgmnt_hdr->addr2[4],pmgmnt_hdr->addr2[5]);
				printf("%s -> ", str);
				if(ssid_len > 0)
				{
					snprintf(str, sizeof(str), "%02x:%02x:%02x:%02x:%02x:%02x",pmgmnt_hdr->addr1[0],
					  pmgmnt_hdr->addr1[1], pmgmnt_hdr->addr1[2], pmgmnt_hdr->addr1[3], pmgmnt_hdr->addr1[4],pmgmnt_hdr->addr1[5]);
					printf("%s    %d    %s\n", str, rssi, ssid);
				}
				else
				{
					snprintf(str, sizeof(str), "%02x:%02x:%02x:%02x:%02x:%02x",pmgmnt_hdr->addr1[0],
					  pmgmnt_hdr->addr1[1], pmgmnt_hdr->addr1[2], pmgmnt_hdr->addr1[3], pmgmnt_hdr->addr1[4],pmgmnt_hdr->addr1[5]);
					printf("%s    %d\n", str, rssi);
				}
#ifdef DBG_ADDRS
				snprintf(str, sizeof(str), "%02x:%02x:%02x:%02x:%02x:%02x",pmgmnt_hdr->addr3[0],
				  pmgmnt_hdr->addr3[1], pmgmnt_hdr->addr3[2], pmgmnt_hdr->addr3[3], pmgmnt_hdr->addr3[4],pmgmnt_hdr->addr3[5]);
				printf("ADDR3: %s -> ", str);
				snprintf(str, sizeof(str), "%02x:%02x:%02x:%02x:%02x:%02x",pmgmnt_hdr->addr3[0],
				  pmgmnt_hdr->addr4[1], pmgmnt_hdr->addr1[2], pmgmnt_hdr->addr1[3], pmgmnt_hdr->addr1[4],pmgmnt_hdr->addr1[5]);
				printf("ADDR4: %s -> ", str);
#endif
        	}
        	CIRCLEQ_REMOVE(&display_head, disp, entries);
        	free(disp);
        	print_frame = 0;
        }
    }

    printf("Disp Thread Exiting");
    return (void*) NULL;
}


/*
 * main sets up the wlan* interface and configures the expiration times used by do_display().
 */
int main(int argc, char *argv[])
{
	char *pcaperr;

	struct entry *desc;
	int res = 0;
	int type = 0;
	int opt;
	void *ret;
    char *dev, errbuf[PCAP_ERRBUF_SIZE];

    dev = NULL;
    while((opt = getopt(argc, argv, "m:f:l:")) != -1)
    {
        switch(opt)
        {

			case 'l':
				printf("Using %s\n", optarg);
				dev = optarg;
				break;
            case 'f':
                printf("csv file name %s\n", optarg);
                csv_file = optarg;
                break;
            case 'm':
                printf("Mode is %s\n", optarg);
                mode = optarg;					//probes, all, cts
                break;
            case '?':
                //printf("unknown option: %c\n", optopt);
                break;
        }
    }
    if(mode == NULL)
    {
    	printf("\nYou must select a mode -m probes, cts, or all\n");
    	exit(1);
    }

    if(strcmp(mode, "all") == 0)
    {
    	capture_mode = all;
    }
    else if(strcmp(mode, "probes") == 0)
    {
    	capture_mode = probes;
    }
    else if(strcmp(mode, "cts") == 0)
    {
    	capture_mode = cts;
        if(csv_file == NULL)
        {
        	printf("\nYou must select a csv file when using the cts option\n");
        	exit(1);
        }
        parse_csv_file(csv_file);
        //sscanf(remote_device, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &remote_mac_arr[0], &remote_mac_arr[1], &remote_mac_arr[2], &remote_mac_arr[3], &remote_mac_arr[4], &remote_mac_arr[5]);
    }
    else
    {
    	capture_mode = probes;
    }
    printf("ProbeMon Engine For Linux\n\n");
    isClosing = 0;
    sem_init(&tx_sem, 0 , -1);
    pthread_mutex_init(&disp_lock, NULL);
	CIRCLEQ_INIT(&rx_head);
	CIRCLEQ_INIT(&display_head);
	signal(SIGQUIT, TermHandler);
	signal(SIGINT,TermHandler);
    handle = pcap_create(dev, errbuf);
    if(handle == NULL)
    {
        printf("pcap_create() failed due to [%s]\n", errbuf);
        return -1;
    }
    res = pcap_set_rfmon(handle, 1);
    if(res != 0)
    {
        printf("pcap_set_rfmon() failed %d\n", res);
        if(res == PCAP_ERROR_RFMON_NOTSUP)
        {
        	printf("Monitor mode not supported on this interface.\n");
        }
        return res;
    }
    res = pcap_activate(handle);

    if(res != 0)
    {
        printf("pcap_activate() failed %d\n", res);
        if(res == PCAP_ERROR_RFMON_NOTSUP)
        {
        	printf("Check wlan interface name, it maybe wrong or else monitor mode not supported.\n");
        }
        pcaperr = pcap_geterr(handle);
        printf("%s\n", pcaperr);
        return res;
    }

    type = pcap_datalink(handle);
    if(type != DLT_IEEE802_11_RADIO)
    {
    	printf("Bad Link Layer Header Type, expected DLT_IEEE802_11_RADIO\n");
    	return type;
    }

    pthread_create(&disp_thread, NULL, &do_print, NULL);
    while(isClosing < 1)
    {
        res = pcap_loop(handle, -1, frame_ready, NULL);
    }

    pthread_join(disp_thread, &ret);
	pcap_close(handle);
	while (!CIRCLEQ_EMPTY(&rx_head))
    {
	    desc = CIRCLEQ_FIRST(&rx_head);
    	free(desc);
    }
	while (!CIRCLEQ_EMPTY(&display_head))
    {
	    desc = CIRCLEQ_FIRST(&display_head);
    	free(desc);
    }
	printf("\nExiting\n");
	return 0;
}



