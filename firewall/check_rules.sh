echo -e "\n================== iptables rules (IPv4) ==================\n"
sudo iptables -L --line-numbers
echo -e "\n================== ip6tables rules (IPv6) ==================\n"
sudo ip6tables -L --line-numbers
