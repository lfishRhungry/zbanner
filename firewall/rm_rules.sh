if \
sudo iptables \
    -t filter \
    -D OUTPUT \
    -p tcp \
    --tcp-flags RST RST \
    -j DROP
then echo -e "Removing TCP RST DROP rule for IPv4 successed!";
else echo -e "Removing TCP RST DROP rule for IPv4 failed...";
fi

if \
sudo ip6tables \
    -t filter \
    -D OUTPUT \
    -p tcp \
    --tcp-flags RST RST \
    -j DROP 
then echo -e "Removing TCP RST DROP rule for IPv6 successed!";
else echo -e "Removing TCP RST DROP rule for IPv4 failed...";
fi

if \
sudo iptables \
    -t filter \
    -D OUTPUT \
    -p icmp \
    --icmp-type 3/3 \
    -j DROP
then echo -e "Removing ICMP Port Unreachable DROP rule for IPv4 successed!";
else echo -e "Removing TCP RST DROP rule for IPv4 failed...";
fi

if \
sudo ip6tables \
    -t filter \
    -D OUTPUT \
    -p icmpv6 \
    --icmpv6-type 1/4 \
    -j DROP
then echo -e "Removing ICMP Port Unreachable DROP rule for IPv6 successed!";
else echo -e "Removing TCP RST DROP rule for IPv4 failed...";
fi
