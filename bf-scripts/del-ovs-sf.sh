sudo ovs-vsctl del-port en3f0pf0sf4
sudo ovs-vsctl del-port en3f0pf0sf5

echo "delete en3f0pf0sf4 en3f0pf0sf5"
sudo ovs-vsctl show
