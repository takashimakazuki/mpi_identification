#include <stdio.h>
#include <stdlib.h>
#include <mpi.h>

#define PROCESSES 2

int main(int argc, char* argv[])
{
    MPI_Init(&argc, &argv);
 
    int size;
    MPI_Comm_size(MPI_COMM_WORLD, &size);
    if(size != PROCESSES)
    {
        printf("This application is meant to be run with %d MPI processes.\n", PROCESSES);
        MPI_Abort(MPI_COMM_WORLD, EXIT_FAILURE);
    }
 
    // Get my rank
    int my_rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &my_rank);
 
    int my_values[PROCESSES];
    for(int i = 0; i < PROCESSES; i++)
    {
        my_values[i] = my_rank * 300 + i * 100;
    }
    printf("Process %d, my values = %d, %d.\n", my_rank, my_values[0], my_values[1]);
 
    int buffer_recv[PROCESSES];
    MPI_Alltoall(&my_values, 1, MPI_INT, buffer_recv, 1, MPI_INT, MPI_COMM_WORLD);
    printf("Values collected on process %d: %d, %d.\n", my_rank, buffer_recv[0], buffer_recv[1]);
 
    MPI_Finalize();
 
    return EXIT_SUCCESS;
}