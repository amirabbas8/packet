#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/vmalloc.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/inet.h>
#include <linux/device.h>
#include <linux/fs.h> 
#include <linux/uaccess.h>
#include <linux/mutex.h>

#define  DEVICE_NAME "ipfilter"
#define  CLASS_NAME  "ipfilterclass" 
static DEFINE_MUTEX(ipfilter_mutex);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Amir Abbas");
MODULE_DESCRIPTION("Filter IP");
MODULE_VERSION("0.1");

static struct nf_hook_ops nfho;

static struct ip_port {
     char ip[50];
}* ips;
static int ip_count=0;
static int    majorNumber;
static struct class*  packetClass  = NULL;
static struct device* packetDevice = NULL;
static int     deviceOpen(struct inode *, struct file *);
static int     deviceRelease(struct inode *, struct file *);
static ssize_t deviceWrite(struct file *, const char *, size_t, loff_t *);
static bool isBlackMode=1;

static struct file_operations fops =
{
   .open = deviceOpen,
   .write = deviceWrite,
   .release = deviceRelease,
};

static bool find_ip(char  ip_str[50]){
	int i;
	for(i=0;i<ip_count;i++){
		if (strcmp(ip_str, ips[i].ip) == 0)
			return 1;
	}
	return 0;

}
static unsigned int my_hook(unsigned int hooknum,struct sk_buff *skb,
const struct net_device *in,const struct net_device *out,int (*okfn)(struct sk_buff *)){

	struct iphdr *iph;
   	struct tcphdr *tcph;
   	struct udphdr *udph;
   	u32 saddr;
	u16 sport;
	char add_port[50];
	if (!skb)
		return NF_DROP;
	iph = ip_hdr(skb);
	if (iph->protocol == IPPROTO_TCP){
		tcph = tcp_hdr(skb); 
		saddr = ntohl(iph->saddr);
		sport = ntohs(tcph->source);
		sprintf(add_port,"%pI4h:%d",&saddr,sport);
		if (find_ip(add_port)){
			if(isBlackMode){
	   			printk("Packet Filter: Dropped TCP packet from %s",add_port);
		    		return NF_DROP;
			}else{
	   			printk("Packet Filter: Accepted TCP packet from %s",add_port);
				return NF_ACCEPT;
			}
		}else{
			if(isBlackMode){	
		   		printk(KERN_INFO "Packet Filter: Accepted TCP packet from %s",add_port);
		    		return NF_ACCEPT;
			}else{
		   		printk(KERN_INFO "Packet Filter: Dropped TCP packet from %s",add_port);
				return NF_DROP;
			}

		}
	}else if (iph->protocol == IPPROTO_UDP){
		udph = udp_hdr(skb); 
		saddr = ntohl(iph->saddr);
		sport = ntohs(udph->source);
		sprintf(add_port,"%pI4h:%d",&saddr,sport);
		if (find_ip(add_port)){
			if(isBlackMode){
	   			printk("Packet Filter: Dropped UDP packet from %s",add_port);
		    		return NF_DROP;
			}else{
	   			printk("Packet Filter: Accepted UDP packet from %s",add_port);
				return NF_ACCEPT;
			}
		}else{
			if(isBlackMode){
		   		printk(KERN_INFO "Packet Filter: Accepted UDP packet from %s",add_port);
		    		return NF_ACCEPT;
			}else{
		   		printk(KERN_INFO "Packet Filter: Dropped UDP packet from %s",add_port);
				return NF_DROP;
			}

		}
	}

	if(isBlackMode){
		printk(KERN_INFO "Packet Filter: Accepted Non-TCP-UDP packet");
		return NF_ACCEPT;
	}else{
		printk(KERN_INFO "Packet Filter: Dropped Non-TCP-UDP packet");
		return NF_DROP;
	}

}

static int __init packet_init(void)
{
     	nfho.hook = (nf_hookfn *)my_hook;
	nfho.hooknum = 0 ; //NF_IP_PRE_ROUTING;
 	nfho.pf = PF_INET;
  	nfho.priority = NF_IP_PRI_FIRST;

    if(nf_register_net_hook(&init_net,&nfho)==0){
		majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
		if (majorNumber<0){
			return majorNumber;
		   }
		packetClass = class_create(THIS_MODULE, CLASS_NAME);
	  	if (IS_ERR(packetClass)){
			unregister_chrdev(majorNumber, DEVICE_NAME);
	      		return -1;
		}
	   	packetDevice = device_create(packetClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
	   	if (IS_ERR(packetDevice)){
			class_destroy(packetClass);
			unregister_chrdev(majorNumber, DEVICE_NAME);
	      		return -1;
	   	}
		mutex_init(&ipfilter_mutex);
		ips = (struct ip_port*)vmalloc(100 * sizeof(struct ip_port));
		printk(KERN_INFO "Start Packet Filter\n");
		return 0;
	}else{
		return -1;
	}
}

static void __exit packet_exit(void)
{
	mutex_destroy(&ipfilter_mutex);
	device_destroy(packetClass, MKDEV(majorNumber, 0));
   	class_unregister(packetClass);
   	class_destroy(packetClass);
   	unregister_chrdev(majorNumber, DEVICE_NAME);
  	nf_unregister_net_hook(&init_net,&nfho); 
  	printk(KERN_INFO "Packet Filter: Finish Packet Filter.\n");
}

static int deviceOpen(struct inode *inodep, struct file *filep){
	if(!mutex_trylock(&ipfilter_mutex)){
 		printk(KERN_ALERT "Packet Filter: Device in use by another process");
		return -EBUSY;
	}
   	printk(KERN_INFO "Packet Filter: config started\n");
   return 0;
}


static ssize_t deviceWrite(struct file *filep, const char *buffer, size_t len, loff_t *offset){
	if(strcmp(buffer,"black")==0){
		isBlackMode=1;
	}else if(strcmp(buffer,"white")==0){
		isBlackMode=0;
	}else{
		if(ip_count<100){
		sprintf(ips[ip_count].ip, "%s", buffer);
		ip_count++;
		}
	}
	return len;
}

static int deviceRelease(struct inode *inodep, struct file *filep){
	mutex_unlock(&ipfilter_mutex);
   	printk(KERN_INFO "Packet Filter: Config closed\n");
   	return 0;
}
module_init(packet_init);
module_exit(packet_exit);
