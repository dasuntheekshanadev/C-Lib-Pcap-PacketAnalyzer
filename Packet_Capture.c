#include <stdio.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

void packetHandler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    static int packetCount = 1;
    
    // Save packet hex output to a file
    FILE *hexFile = fopen("hexValues.txt", "a");
    if (hexFile == NULL) {
        printf("File Not Found.\n");
        return;
    }
    
    // Save packet info in readable format to a file
    FILE *infoFile = fopen("details.com.txt", "a");
    if (infoFile == NULL) {
        printf("File Not Found.\n");
        fclose(hexFile);
        return;
    }
    
    fprintf(hexFile, "**********************\n");
    fprintf(hexFile, "Packet %d\n", packetCount);
    fprintf(hexFile, "**********************\n");
    
    if (pkthdr->caplen < sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr)) {
        printf("Packet size is too small.\n");
        fclose(hexFile);
        fclose(infoFile);
        return;
    }
    
    for (int i = 0; i < pkthdr->caplen; i++) {
        fprintf(hexFile, "%02x ", packet[i]);
        if ((i + 1) % 16 == 0)
            fprintf(hexFile, "\n");
    }
    fprintf(hexFile, "\n");
    
    // Extract Ethernet header
    struct ethhdr *eth = (struct ethhdr *)packet;
    
    // Extract IP header
    if (pkthdr->caplen < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
        printf("Packet size is too small to extract IP header.\n");
        fclose(hexFile);
        fclose(infoFile);
        return;
    }
    struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ethhdr));
    
    // Extract TCP header
    if (pkthdr->caplen < sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr)) {
        printf("Packet size is too small to extract TCP header.\n");
        fclose(hexFile);
        fclose(infoFile);
        return;
    }
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
    
    // Extract payload data
    const u_char *payload = packet + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);

    // Convert source and destination IP addresses to readable format
    char sourceIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->saddr), sourceIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->daddr), destIP, INET_ADDRSTRLEN);
    
    // Write packet info to the info file
    fprintf(infoFile, "Packet %d:\n", packetCount);
    fprintf(infoFile, "%02x:%02x:%02x:%02x:%02x:%02x|%02x:%02x:%02x:%02x:%02x:%02x|%s|%s|%d|%d|%d|",
            eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5],
            eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5],
            sourceIP, destIP, ip->protocol, ntohs(tcp->source), ntohs(tcp->dest));
    
    // Print payload data
    int payloadLength = pkthdr->caplen - sizeof(struct ethhdr) - sizeof(struct iphdr) - sizeof(struct tcphdr);
    for (int i = 0; i < payloadLength; i++) {
        fprintf(infoFile, "%02x ", payload[i]);
    }
    fprintf(infoFile, "\n");
    
    fclose(hexFile);
    fclose(infoFile);
    packetCount++;
}


int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    pcap_if_t *alldevs, *dev;
    
    // Find all network devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("Error finding devices: %s\n", errbuf);
        return 1;
    }
    
    // Use the first device in the list
    dev = alldevs;
    
    // Open the network device for packet capture
    handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("Could not open device %s: %s\n", dev->name, errbuf);
        pcap_freealldevs(alldevs);
        return 1;
    }
    
    // Capture packets
    pcap_loop(handle, 0, packetHandler, NULL);
    
    // Close the packet capture session
    pcap_close(handle);
    pcap_freealldevs(alldevs);
    
    return 0;
}
