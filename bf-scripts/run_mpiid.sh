sudo ovs-vsctl del-port  p0
sudo ovs-vsctl add-port ovsbr0 p0

sudo /tmp/log_mpi -a auxiliary:mlx5_core.sf.4 -a auxiliary:mlx5_core.sf.5 -- --nr_queues 3 --hw_offload 0 --rx_only 0 --stats_timer 1
