#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "constants.h"
#include "modes.h"
#include "nist.h"
#include "math.h"

void parse_key(char* key, struct md6_config* config);
void parse_args(int argc, char* argv[], struct md6_config* config);
void print_output(uint64* output, uint16 digest_size);

int tamanho(FILE* f){
    int t;
    fseek(f, 0, SEEK_END);
    t = ftell (f);
    rewind(f);
    return t;
}
int main (int argc, char* argv[]) {
    //Entradas
    FILE* file=fopen(argv[1],"rb");
    //Calcula tamanho do arquivo
    int tam=tamanho(file);
    //Calcula quantidade de blocos
    if(tam%512){
        tam+=512-tam%512;
    }
    tam/=4;
    //buffer de leitura
    unsigned char buf[512];
    //block de entrada 512B
    unsigned long long int in[64+25];
    //block de saida 128B
    unsigned long long int out[16];
    //Memoria necessaria para arvora 1/4 do tamanho do arquivo (mais complemento do block)
    unsigned char data[tam];
    //Variaveis usadas
    int bytes,i,index=0;

    //Inicialização do md6
    hashState state;
    Init(&state, 0);
    // Set default parameters:
    state.config.keylen = 0; // implies key is nil
    memset(state.config.key, 0, MAX_KEYLEN);
    state.config.max_level = 64;
    state.config.digest_size = atoi(argv[2]); // This must be specified!
    state.config.rounds = 40 + (state.config.digest_size / 4);

    //Base da arvore
    if(tam>128){
        while((bytes=fread(buf,sizeof(char),512,file))){
            if(bytes!=512){
                //Block parcial
                for(i=bytes;i<512;i++){
                    buf[i]=0x0;
                }
                memcpy(&(in[25]),buf,512);
                reverse_buffer_byte_order(&(in[25]),64);
                initialize_buf(in, &(state.config),
                     0, 4096-(bytes*8), (uint8)(1), index);

            }else {
                //Block completo
                memcpy(&(in[25]),buf,512);
                reverse_buffer_byte_order(&(in[25]),64);
                initialize_buf(in, &(state.config),
                     0, 0, (uint8)(1), index);
            }
            f(in,out,state.config.rounds);
            memcpy(&(data[index*128]),out,128);
            index++;
        }
        //i = quantidade de blocks de saida 128B
        i=tam/128;

        //Level atual
        int current_level=2;

        //Resto da arvore
        while(i>4){
            int current_index, current_blocks_num;
            for(current_index=0,current_blocks_num=i/4;current_index<current_blocks_num;current_index++){
                //Block completo
                memcpy(&(in[25]),&(data[current_index*512]),512);
                initialize_buf(in, &(state.config),
                     0, 0, (uint8)(current_level), current_index);
                f(in,out,state.config.rounds);
                memcpy(&(data[current_index*128]),out,128);
            }
            if(i%4){
                //Block parcial
                memcpy(&(in[25]),&(data[current_index*512]),(i%4)*128);
                int j;
                for(j=(i%4)*16+25;j<89;j++)
                    in[j]=0x0;
                initialize_buf(in, &(state.config),
                     0, 4096-(i%4)*1024, (uint8)(current_level), current_index);
                f(in,out,state.config.rounds);
                memcpy(&(data[current_index*128]),out,128);
                current_index++;
            }
            //Nova quantidade de blocks de saida 128B
            i=ceil(i/4.0);
            //Subir um level
            current_level++;

        }
        //Ultima compressão
        if(i%4){
            //Block parcial
            memcpy(&(in[25]),data,(i%4)*128);
            int j;
            for(j=(i%4)*16+25;j<89;j++)
                in[j]=0x0;
            initialize_buf(in, &(state.config),
                 1, 4096-(i%4)*1024, (uint8)(current_level), 0);
            f(in,out,state.config.rounds);
            memcpy(&(data[0]),out,128);
        } else {
            //Block completo
            memcpy(&(in[25]),data,512);
            initialize_buf(in, &(state.config),
                 1, 0, (uint8)(current_level), 0);
            f(in,out,state.config.rounds);
            memcpy(data,out,128);
        }
    } else {
        bytes=fread(buf,sizeof(char),512,file);
        if(bytes!=512){
                //Block parcial
                for(i=bytes;i<512;i++){
                    buf[i]=0x0;
                }
                memcpy(&(in[25]),buf,512);
                reverse_buffer_byte_order(&(in[25]),64);
                initialize_buf(in, &(state.config),
                     1, 4096-(bytes*8), (uint8)(1), 0);

            }else {
                //Block completo
                memcpy(&(in[25]),buf,512);
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

void parse_args(int argc, char* argv[], struct md6_config* config) {
  int i;
  int num_rounds = -1;

  // Set default parameters:
  config->keylen = 0; // implies key is nil
  memset(config->key, 0, MAX_KEYLEN);
  config->max_level = 64;
  config->digest_size = 0; // This must be specified!
  config->rounds = 104;    // Determined from digest size

  for(i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-k") == 0 ||
	strcmp(argv[i], "--key") == 0) {
      parse_key(argv[i+1], config);
      i++;
    } else if (strcmp(argv[i], "-d") == 0 ||
	       strcmp(argv[i], "--digest-size") == 0) {
      config->digest_size = atoi(argv[i + 1]);
      i++;
    } else if (strcmp(argv[i], "-L") == 0 ||
	       strcmp(argv[i], "--level") == 0) {
      config->max_level = atoi(argv[i + 1]);
      i++;
    } else if (strcmp(argv[i], "-r") == 0 ||
	       strcmp(argv[i], "--rounds") == 0) {
      num_rounds = atoi(argv[i + 1]);
      i++;
    } else if (strcmp(argv[i], "-i") == 0) {
      debug = atoi(argv[i + 1]);
    } else if (strcmp(argv[i], "-h") == 0 ||
	       strcmp(argv[i], "--help") == 0) {
      printf("\nmd6 usage: \n");
      printf("md6 -d <digest_size> < <filename>\n");
      printf("\nOptions:\n");
      printf("-k, --key <key>        Use <key> in the compression function\n");
      printf("-L, --level <level>    Specify the maximum level for PAR operation\n");
      printf("-r, --rounds <rounds>  Run the compression function for <rounds>\n");
      printf("-i <debug level>       How much debug output. 0 is least, 2 is most\n");
      printf("-h, --help             Print this help and exit\n\n");
      exit(0);
    }
  }

  if (num_rounds != -1) {
    config->rounds = num_rounds;
  } else {
    config->rounds = md6_default_r(config->digest_size, config->keylen);
  }

  if (config->digest_size < 1 || config->digest_size > 512) {
    printf("digest size must be between 1 and 512 (inclusive)\n\n");
    exit(1);
  } else if (config->rounds > 0x0fff) {
    printf("rounds must be between 1 and %d (inclusive)\n\n", 0x0fff);
  }
}

void parse_key(char* key, struct md6_config* config) {
  int i;

  // Make sure key is an appropriate size
  config->keylen = strlen(key);
  if (config->keylen > MAX_KEYLEN) {
    printf("key must be between 1 and 64 bytes.\n\n");
    exit(1);
  }
  // Copy the key into the md6_config struct,
  // converting from big endian to little endian.
  for (i = 0; i < config->keylen; i++) {
    // index in argv to avoid array out of bounds.
    // config->key has already been zeroed out,
    (config->key)[8*(i/8) + 7 - (i % 8)] = key[i];
  }
  // Add zero bytes to finish off the key.
  for (;i % 8 != 0; i++) {
    (config->key)[8*(i/8) + 7 - (i % 8)] = 0;
  }
}


