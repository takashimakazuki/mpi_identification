CC := mpicc

.PHONY: clean mpi_send_loop sd_loop

clean:
	rm mpi_send_loop

mpi_send_loop:
	mpicc -o mpi_send_loop mpi_send_loop.c

sd_loop:
	mpirun -np 2 --hostfile hosts ./mpi_senf_loop &
	#sar -r 1 20 -o "$(OUT_FILE).log" 2>&1 > /dev/null
