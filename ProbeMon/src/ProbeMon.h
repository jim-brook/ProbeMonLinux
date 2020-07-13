#include <linux/types.h>
#include <linux/if_ether.h>
#include <asm/byteorder.h>
#define SSID_OFFSET 25
#define RSSI_OFFSET 14
/* frame types */
#define RTW_IEEE80211_FTYPE_MGMT		0x0000
#define RTW_IEEE80211_FTYPE_CTL		0x0004
#define RTW_IEEE80211_FTYPE_DATA		0x0008
#define RTW_IEEE80211_FTYPE_EXT		0x000c

/* management */
#define RTW_IEEE80211_STYPE_ASSOC_REQ	0x0000
#define RTW_IEEE80211_STYPE_ASSOC_RESP	0x0010
#define RTW_IEEE80211_STYPE_REASSOC_REQ	0x0020
#define RTW_IEEE80211_STYPE_REASSOC_RESP	0x0030
#define RTW_IEEE80211_STYPE_PROBE_REQ	0x0040
#define RTW_IEEE80211_STYPE_PROBE_RESP	0x0050
#define RTW_IEEE80211_STYPE_BEACON		0x0080
#define RTW_IEEE80211_STYPE_ATIM		0x0090
#define RTW_IEEE80211_STYPE_DISASSOC	0x00A0
#define RTW_IEEE80211_STYPE_AUTH		0x00B0
#define RTW_IEEE80211_STYPE_DEAUTH		0x00C0
#define RTW_IEEE80211_STYPE_ACTION		0x00D0

/* control */
#define RTW_IEEE80211_STYPE_CTL_EXT		0x0060
#define RTW_IEEE80211_STYPE_BACK_REQ		0x0080
#define RTW_IEEE80211_STYPE_BACK		0x0090
#define RTW_IEEE80211_STYPE_PSPOLL		0x00A0
#define RTW_IEEE80211_STYPE_RTS		0x00B0
#define RTW_IEEE80211_STYPE_CTS		0x00C0
#define RTW_IEEE80211_STYPE_ACK		0x00D0
#define RTW_IEEE80211_STYPE_CFEND		0x00E0
#define RTW_IEEE80211_STYPE_CFENDACK		0x00F0

/* data */
#define RTW_IEEE80211_STYPE_DATA		0x0000
#define RTW_IEEE80211_STYPE_DATA_CFACK	0x0010
#define RTW_IEEE80211_STYPE_DATA_CFPOLL	0x0020
#define RTW_IEEE80211_STYPE_DATA_CFACKPOLL	0x0030
#define RTW_IEEE80211_STYPE_NULLFUNC	0x0040
#define RTW_IEEE80211_STYPE_CFACK		0x0050
#define RTW_IEEE80211_STYPE_CFPOLL		0x0060
#define RTW_IEEE80211_STYPE_CFACKPOLL	0x0070
#define RTW_IEEE80211_STYPE_QOS_DATA		0x0080
#define RTW_IEEE80211_STYPE_QOS_DATA_CFACK		0x0090
#define RTW_IEEE80211_STYPE_QOS_DATA_CFPOLL		0x00A0
#define RTW_IEEE80211_STYPE_QOS_DATA_CFACKPOLL	0x00B0
#define RTW_IEEE80211_STYPE_QOS_NULLFUNC	0x00C0
#define RTW_IEEE80211_STYPE_QOS_CFACK		0x00D0
#define RTW_IEEE80211_STYPE_QOS_CFPOLL		0x00E0
#define RTW_IEEE80211_STYPE_QOS_CFACKPOLL	0x00F0
struct frame_types_desc
{
	uint32_t frame_type;
	uint32_t frame_sub_type;
};

struct ieee80211_radiotap_header {
	/**
	 * @it_version: radiotap version, always 0
	 */
	uint8_t it_version;

	/**
	 * @it_pad: padding (or alignment)
	 */
	uint8_t it_pad;

	/**
	 * @it_len: overall radiotap header length
	 */
	__le16 it_len;

	/**
	 * @it_present: (first) present word
	 */
	__le32 it_present;
} __packed;

struct ieee80211_hdr {
	__le16 frame_control;
	__le16 duration_id;
	u_int8_t addr1[ETH_ALEN];
	u_int8_t addr2[ETH_ALEN];
	u_int8_t addr3[ETH_ALEN];
	__le16 seq_ctrl;
	u_int8_t addr4[ETH_ALEN];
} __attribute__((aligned(2),packed));

struct entry
{
		u_char *packet;
		int packet_size;
		CIRCLEQ_ENTRY(entry) entries;

}*n1, *n2, *np;

enum cap_mode
{
	all,
	probes,
	cts
};

void* do_print(void *arg);
