sudo ovs-vsctl add-port ovsbr1 en3f0pf0sf5
sudo ovs-vsctl add-port ovsbr0 en3f0pf0sf4

echo "add en3f0pf0sf5 en3f0pf0sf4"
sudo ovs-vsctl show
