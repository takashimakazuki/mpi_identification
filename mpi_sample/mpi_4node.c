#include "mpi.h"
#include <stdio.h>

int main(int argc, char **argv)
{
    int world_size;
    int world_rank;
    int number;

    MPI_Init(&argc, &argv);
    MPI_Comm_size(MPI_COMM_WORLD, &world_size);
    MPI_Comm_rank(MPI_COMM_WORLD, &world_rank);

    if (world_rank == 0)
    {
        number = 0xdeadbeef;
        MPI_Send(&number, 1, MPI_INT, 1, 0xaa, MPI_COMM_WORLD);
    }
    else if (world_rank == 1)
    {
        MPI_Recv(&number, 1, MPI_INT, 0, 0xaa, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
    }

    MPI_Finalize();
}
