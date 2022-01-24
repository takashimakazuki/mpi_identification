CC := mpicc

.PHONY: clean mpi_bcast_loop bc_loop

clean:
	rm mpi_bcast_loop

mpi_bcast_loop:
	mpicc -o mpi_bcast_loop mpi_bcast_loop.c

bc_loop:
	mpirun -np 2 --hostfile hosts ./mpi_bcast_loop &
	sar -r 1 20 -o "$(OUT_FILE).log" 2>&1 > /dev/null
