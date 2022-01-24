#include "mpi.h"
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#define BCAST_LOOP 100
#define SEND_LOOP 100

int main(int argc, char **argv)
{
    MPI_Status status;
    // Initialize the MPI environment
    MPI_Init(&argc, &argv);

    // Get the number of processes
    int world_size;
    MPI_Comm_size(MPI_COMM_WORLD, &world_size);

    // Get the rank of the process
    int world_rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &world_rank);

    int number;

    int batch_size = 100;
    for (int batch_index = 0; batch_index < batch_size; batch_index++)
    {
        for (int i = 0; i < SEND_LOOP; i++)
        {
            for (int loop = 0; loop < 1000000; loop++)
            {
                number++;
            }

            if (world_rank == 0)
            {
                MPI_Send(&number, 1, MPI_INT, 1, 0xa0 + batch_index, MPI_COMM_WORLD);
            }
            else if (world_rank == 1)
            {
                MPI_Recv(&number, 1, MPI_INT, 0, 0xa0 + batch_index, MPI_COMM_WORLD, &status);
            }
        }

        if (world_rank == 0)
        {
            printf("finish batch %d\n", batch_index);
        }
    }

    // Finalize the MPI environment.
    MPI_Finalize();
}