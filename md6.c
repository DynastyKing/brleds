#include <sys/time.h>
#include <time.h>
#include <sys/resource.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "constants.h"
#include "modes.h"
#include "nist.h"
#include "math.h"
#include <mpi.h>

void print_output(uint64* output, uint16 digest_size);

unsigned int tamanho(FILE* f){
    unsigned int t;
    fseek(f, 0, SEEK_END);
    t = ftell (f);
    rewind(f);
    return t;
}
unsigned int nextBlocksNum(unsigned int * a){
    if(*a%4){
        *a=*a/4+1;
    } else {
        *a=*a/4;
    }
}
int main (int argc, char* argv[]) {
    int rank;
    int size;


    MPI_Init(&argc, &argv);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);
    //Entradas
    //Calcula tamanho do arquivo
    unsigned int tam;
    unsigned int blocks;
    //Memoria necessaria para arvora 1/4 do tamanho do arquivo (mais complemento do block)
    unsigned char * data;
    unsigned char * buf;
    //block de entrada 512B
    unsigned long long int in[89];
    //block de saida 128B
    unsigned long long int out[16];
    //Variaveis usadas
    int bytes,i,j,index=0;
    int current_index, current_blocks_num;

    //Inicialização do md6
    hashState state;
    Init(&state, 0);
    // Set default parameters:
    state.config.keylen = 0; // implies key is nil
    memset(state.config.key, 0, MAX_KEYLEN);
    state.config.max_level = 64;
    state.config.digest_size = atoi(argv[2]); // This must be specified!
    state.config.rounds = 40 + (state.config.digest_size / 4);
    if(rank==0){
        struct timespec ts_start;
        struct timespec ts_end;
        clock_gettime(CLOCK_MONOTONIC, &ts_start);
        FILE* file=fopen(argv[1],"rb");
        tam=tamanho(file);
        blocks=tam/512;
        if(tam%512)
            blocks++;
        data=(unsigned char *) malloc(blocks*512);
        //arquivo tiver mais de um bloco
        if(tam>512){
            if(size>1)
                MPI_Bcast(&tam,1,MPI_UNSIGNED, 0,MPI_COMM_WORLD);
            bytes=fread(data,sizeof(char),tam,file);
            fclose(file);
            if(size>1)
                MPI_Bcast(data,tam,MPI_CHAR, 0,MPI_COMM_WORLD);
            for(i=rank;i<blocks;i+=size){
                if(i==blocks-1){
                    bytes=tam-i*512;
                } else {
                    bytes=512;
                }
                memcpy(&(in[25]),&(data[i*512]),bytes);
                buf=(unsigned char *) &(in[25]);
                for(j=bytes;j<512;j++){
                    buf[j]=0x0;
                }
                reverse_buffer_byte_order(&(in[25]),64);
                initialize_buf(in, &(state.config),
                     0, 4096-(bytes*8), (uint8)(1), i);
                f(in,out,state.config.rounds);
                memcpy(&(data[i*128]),out,128);
            }

            if(size>1){
                MPI_Barrier(MPI_COMM_WORLD);
                for(i=0;i<blocks;i++){
                    MPI_Bcast(&(data[i*128]),128,MPI_CHAR, i%size,MPI_COMM_WORLD);
                }
            }
            tam=blocks*128;
            nextBlocksNum(&blocks);
            //Level atual
            int current_level=2;

            //Resto da arvore
            while(blocks>1){
                for(current_index=rank;current_index<blocks;current_index+=size){
                    if(current_index==blocks-1&&tam-current_index*512!=0){
                        //Block parcial
                        memcpy(&(in[25]),&(data[current_index*512]),tam-current_index*512);
                        for(j=(tam-current_index*512)/8+25;j<89;j++)
                            in[j]=0x0;
                        initialize_buf(in, &(state.config),
                             0, 4096-(tam-current_index*512)*8, (uint8)(current_level), current_index);
                        f(in,out,state.config.rounds);
                        memcpy(&(data[current_index*128]),out,128);
                    } else {
                        //Block completo
                        memcpy(&(in[25]),&(data[current_index*512]),512);
                        initialize_buf(in, &(state.config),
                             0, 0, (uint8)(current_level), current_index);
                        f(in,out,state.config.rounds);
                        memcpy(&(data[current_index*128]),out,128);
                    }
                }
                //Subir um level
                current_level++;
                if(size>1){
                    MPI_Barrier(MPI_COMM_WORLD);
                    for(i=0;i<blocks;i++){
                        MPI_Bcast(&(data[i*128]),128,MPI_CHAR, i%size,MPI_COMM_WORLD);
                    }
                }
                tam=blocks*128;
                nextBlocksNum(&blocks);
                if(size>1)
                    MPI_Barrier(MPI_COMM_WORLD);

            }
            //Ultima compressão
            if(tam!=512){
                //Block parcial
                memcpy(&(in[25]),data,tam);
                int j;
                for(j=(tam/8)+25;j<89;j++)
                    in[j]=0x0;
                initialize_buf(in, &(state.config),
                     1, 4096-(tam)*8, (uint8)(current_level), 0);
                f(in,out,state.config.rounds);
            } else {
                //Block completo
                memcpy(&(in[25]),data,512);
                initialize_buf(in, &(state.config),
                     1, 0, (uint8)(current_level), 0);
                f(in,out,state.config.rounds);
            }
        } else {
            bytes=fread(data,sizeof(char),tam,file);
            fclose(file);
            if(bytes!=512){
                //Block parcial
                memcpy(&(in[25]),data,bytes);
                buf=(unsigned char *) &(in[25]);
                for(i=bytes;i<512;i++){
                    buf[i]=0x00;
                }
                reverse_buffer_byte_order(&(in[25]),64);
                initialize_buf(in, &(state.config),
                     1, 4096-(bytes*8), (uint8)(1), 0);

            }else {
                //Block completo
                memcpy(&(in[25]),data,512);
                reverse_buffer_byte_order(&(in[25]),64);
                initialize_buf(in, &(state.config),
                     1, 0, (uint8)(1), 0);
            }
            f(in,out,state.config.rounds);
        }
        printf("digest (%d bits): \n",state.config.digest_size);
        truncate_buf(out,state.config.digest_size,16);
        reverse_buffer_byte_order(out,16);
        print_output(out,state.config.digest_size);
        printf("\n");
        clock_gettime(CLOCK_MONOTONIC, &ts_end);
        printf("Ini: %ld.%.9ld\n", ts_start.tv_sec, ts_start.tv_nsec);
        printf("Fim: %ld.%.9ld\n", ts_end.tv_sec, ts_end.tv_nsec);
    } else { //Rank != 0
        MPI_Bcast(&tam,1,MPI_UNSIGNED, 0,MPI_COMM_WORLD);
        blocks=tam/512;
        if(tam%512)
            blocks++;
        data=(char *) malloc(tam);
        if(tam>512){
            MPI_Bcast(data,tam,MPI_CHAR, 0,MPI_COMM_WORLD);
            for(i=rank;i<blocks;i+=size){
                if(i==blocks-1){
                    bytes=tam-i*512;
                } else {
                    bytes=512;
                }
                memcpy(&(in[25]),&(data[i*512]),bytes);
                buf=(unsigned char *) &(in[25]);
                for(j=bytes;j<512;j++){
                    buf[j]=0x0;
                }
                reverse_buffer_byte_order(&(in[25]),64);
                initialize_buf(in, &(state.config),
                     0, 4096-(bytes*8), (uint8)(1), i);
                f(in,out,state.config.rounds);
                memcpy(&(data[i*128]),out,128);
            }

            if(size>1){
                MPI_Barrier(MPI_COMM_WORLD);
                for(i=0;i<blocks;i++){
                    MPI_Bcast(&(data[i*128]),128,MPI_CHAR, i%size,MPI_COMM_WORLD);
                }
            }
            tam=blocks*128;
            nextBlocksNum(&blocks);
            //Level atual
            int current_level=2;

            //Resto da arvore
            while(blocks>1){
                for(current_index=rank;current_index<blocks;current_index+=size){
                    if(current_index==blocks-1&&tam-current_index*512!=0){
                        //Block parcial
                        memcpy(&(in[25]),&(data[current_index*512]),tam-current_index*512);
                        for(j=(tam-current_index*512)/8+25;j<89;j++)
                            in[j]=0x0;
                        initialize_buf(in, &(state.config),
                             0, 4096-(tam-current_index*512)*8, (uint8)(current_level), current_index);
                        f(in,out,state.config.rounds);
                        memcpy(&(data[current_index*128]),out,128);
                    } else {
                        //Block completo
                        memcpy(&(in[25]),&(data[current_index*512]),512);
                        initialize_buf(in, &(state.config),
                             0, 0, (uint8)(current_level), current_index);
                        f(in,out,state.config.rounds);
                        memcpy(&(data[current_index*128]),out,128);
                    }
                }
                //Subir um level
                current_level++;
                if(size>1){
                    MPI_Barrier(MPI_COMM_WORLD);
                    for(i=0;i<blocks;i++){
                        MPI_Bcast(&(data[i*128]),128,MPI_CHAR, i%size,MPI_COMM_WORLD);
                    }
                }
                tam=blocks*128;
                nextBlocksNum(&blocks);
                if(size>1)
                    MPI_Barrier(MPI_COMM_WORLD);

            }
        }
    }
    MPI_Finalize();
}

void print_output(uint64* output, uint16 digest_size) {
  int i;
  int shift;
  uint8 cur_byte;

  // Output is printed in hex with config.digest_size / 8 bytes.
  // Compute a shift to move any 0 padding to the end.
  shift = (8 - (digest_size%8));
  if (shift == 8) {
    shift = 0;
  }

  for (i = (1024 - digest_size)/8; i < 128; i++) {
    cur_byte = ((uint8 *)output)[i] << shift;
    if (i+ 1 < 128) {
      cur_byte |= ((uint8 *)output)[1 + i] >> (8 - shift);
    }
    printf("%02x", cur_byte);
  }
}
