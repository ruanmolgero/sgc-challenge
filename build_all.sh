#!/bin/bash

NC='\033[0m'
RED='\033[1;31m'
YELLOW='\033[1;33m'


echo -e "${YELLOW}Compilando imagem Docker...${NC}"
docker build -t sgc-challenge-ruan . --no-cache
echo -e "${YELLOW}Imagem compi  lada com tag: sgc-challenge-ruan${NC}"

echo -e "${YELLOW}Compilando e rodando desafio${NC}"
docker run --rm -it -v $(pwd):/sgc-challenge-ruan -w /sgc-challenge-ruan sgc-challenge-ruan bash -c "./build.sh && ./challenge"
