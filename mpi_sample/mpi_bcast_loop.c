#include "mpi.h"
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#define EXECUTION_TIME 3 // 実行時間(s)

int main(int argc, char **argv)
{
    // Initialize the MPI environment
    MPI_Init(&argc, &argv);

    // Get the number of processes
    int world_size;
    MPI_Comm_size(MPI_COMM_WORLD, &world_size);

    // Get the rank of the process
    int world_rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &world_rank);

    int number;
    time_t start_t;
    time_t now_t;
    time(&start_t);
    time(&now_t);
    while (difftime(now_t, start_t) < EXECUTION_TIME)
    {
        sleep(1);
        MPI_Bcast(&number, 1, MPI_INT, 0, MPI_COMM_WORLD);
        time(&now_t);
    }

    // Finalize the MPI environment.
    MPI_Finalize();
}