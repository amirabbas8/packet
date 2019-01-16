# BlockIP
a linux kernel module for blocking IP:port udp and tcp packets

# compatibility
this code tested on Arch linux with linux kernel 4.14.88-1-lts

# features
  black & white list modes
  block ips with ports

# how to use
install lts linux kernel

install linux lts headers

change Makefile linux kernel header path to your kernel path

run:

    make
  
    sudo insmod -f packet.ko
