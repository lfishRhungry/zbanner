if \
sudo iptables \
    -A OUTPUT \
    -p tcp \
    --tcp-flags RST RST \
    -j DROP;
then echo -e "Adding TCP RST DROP rule for IPv4 successed!";
else echo -e "Adding TCP RST DROP rule for IPv4 failed...";
fi

if \
sudo ip6tables \
    -A OUTPUT \
    -p tcp \
    --tcp-flags RST RST \
    -j DROP
then echo -e "Adding TCP RST DROP rule for IPv6 successed!";
else echo -e "Adding TCP RST DROP rule for IPv4 failed...";
fi

if \
sudo iptables \
    -A OUTPUT \
    -p icmp \
    --icmp-type 3/3 \
    -j DROP
then echo -e "Adding ICMP Port Unreachable DROP rule for IPv4 successed!";
else echo -e "Adding TCP RST DROP rule for IPv4 failed...";
fi

if \
sudo ip6tables \
    -A OUTPUT \
    -p icmpv6 \
    --icmpv6-type 1/4 \
    -j DROP
then echo -e "Adding ICMP Port Unreachable DROP rule for IPv6 successed!";
else echo -e "Adding TCP RST DROP rule for IPv4 failed...";
fi