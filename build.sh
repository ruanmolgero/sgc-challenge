#!/bin/bash

NC='\033[0m'
RED='\033[1;31m'
YELLOW='\033[1;33m'

echo -e "${YELLOW}Compilando desafio${NC}"
cmake -H. -Bbuild 
cmake --build build
mv build/challenge challenge
echo -e "${YELLOW}Para executar rode ./challenge${NC}"
