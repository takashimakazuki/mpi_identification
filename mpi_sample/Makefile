CC := mpicc

.PHONY: clean mpi_send_loop sd_loop mpi_alltoall  mpi_bcast

clean:
	rm mpi_send_loop

mpi_send_loop:
	mpicc -o mpi_send_loop mpi_send_loop.c

sd_loop:
	mpirun -np 2 --hostfile hosts ./mpi_send_loop 
	#sar -r 1 20 -o "$(OUT_FILE).log" 2>&1 > /dev/null

mpi_alltoall:
	mpicc -o mpi_alltoall mpi_alltoall.c
	scp mpi_alltoall orchestrator:/home/expether/mpi_identification/mpi_sample/
	scp mpi_alltoall deepl:/home/expether/mpi_identification/mpi_sample/
	scp mpi_alltoall rdstore:/home/expether/mpi_identification/mpi_sample/

mpi_bcast:
	mpicc -o mpi_bcast mpi_bcast.c
	scp mpi_bcast orchestrator:/home/expether/mpi_identification/mpi_sample/
	scp mpi_bcast deepl:/home/expether/mpi_identification/mpi_sample/
	scp mpi_bcast rdstore:/home/expether/mpi_identification/mpi_sample/