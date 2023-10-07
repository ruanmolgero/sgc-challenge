## Desafio LabSEC - SGC Challenge

O desafio propôs ao aluno um estudo acerca do assunto de assinatura digital, mais especificamente era necessário a implementação de um protocolo de assinaturas múltiplas, para isso, era necessário o uso do wrapper da biblioteca "OpenSSL" chamado libcryptosec, desenvolvido pelo próprio laboratório.


## Como buildar a imagem docker

```
$ docker build -t sgc-challenge-ruan . --no-cache 
```

## Como buildar desafio

```
$ docker run --rm -it -v $(pwd):/sgc-challenge-ruan -w /sgc-challenge-ruan sgc-challenge-ruan bash
$./build.sh
$./challenge
```

## build_all.sh
Caso deseje rodar o projeto completo também foi fornecida uma shell que agrega ambos os passos anteriores.

```
./build_all.sh
```