#include <string>
#include <fstream>
// libcryptosec
#include <libcryptosec/MessageDigest.h>
#include <libcryptosec/RSAKeyPair.h>
// popper/glib (pdf libs)
// #include <glib-2.0/glib-object.h>
// #include <poppler/glib/poppler.h>

int main(int argc, char **argv)
{
    // Generating keys/saving them on files
    try
    {
        const int num_operators = 3;
        for (int i = 0; i < num_operators; i++)
        {
            // Criação pares de chaves
            RSAKeyPair rsa_key_pair(2048);
            PublicKey *public_key = rsa_key_pair.getPublicKey();
            PrivateKey *private_key = rsa_key_pair.getPrivateKey();
            // Conversão de chaves para o formato PEM
            std::string public_key_pem = public_key->getPemEncoded();
            std::string private_key_pem = private_key->getPemEncoded();

            // Crie nomes de arquivo exclusivos para cada par de chaves
            std::stringstream public_key_filename;
            public_key_filename << ".keys/public_key_" << i << ".pem";
            std::stringstream private_key_filename;
            private_key_filename << ".keys/private_key_" << i << ".pem";

            std::ofstream public_key_file(public_key_filename.str());
            std::ofstream private_key_file(private_key_filename.str());
            if (!public_key_file || !private_key_file)
            {
                std::cerr << "Erro ao abrir os arquivos de chave." << std::endl;
                return 1;
            }

            public_key_file << public_key_pem;
            private_key_file << private_key_pem;

            public_key_file.close();
            private_key_file.close();

            std::cout << "Par de chaves " << i << " salvo em " << public_key_filename.str() << " e " << private_key_filename.str() << "." << std::endl;

            delete public_key;
            delete private_key;
        }
    }
    catch (const AsymmetricKeyException &e)
    {
        std::cerr << "Erro ao criar o par de chaves: " << e.what() << std::endl;
        return 1;
    }

    // std::cout << chave_teste.getPublicKey()->getPemEncoded() << std::endl;
    // std::cout << *ptrChavePublica << std::endl;

    return 0;
}
