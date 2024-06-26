#For allowing Your machine to do NAT Translation
sudo iptables -t nat -A POSTROUTING -o enp0s3 -j MASQUERADE
