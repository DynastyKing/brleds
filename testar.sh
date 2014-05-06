sh compilar_padrao.sh
sh compilar_modificado.sh
./md6_modificado $1 $2 > md6.txt
./md6_padrao -d $2 < $1 > md6padrao.txt
diff md6.txt md6padrao.txt
