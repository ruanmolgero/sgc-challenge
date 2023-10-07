#include <string>
#include <iostream>
#include <fstream>
#include <iomanip>
// libcryptosec
#include <libcryptosec/MessageDigest.h>
#include <libcryptosec/RSAKeyPair.h>
#include <libcryptosec/ByteArray.h>
#include <libcryptosec/PublicKey.h>
#include <libcryptosec/PrivateKey.h>
#include <libcryptosec/RSAPublicKey.h>
#include <libcryptosec/RSAPrivateKey.h>
#include <libcryptosec/Signer.h>
// openssl
#include <openssl/sha.h>
#include <openssl/pem.h>

void create_keys()
{
    // Generating keys/saving them on files
    try
    {
        const int num_operators = 1;
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

            std::ofstream public_key_file(public_key_filename.str(), std::ios::binary | std::ios::in | std::ios::out);
            std::ofstream private_key_file(private_key_filename.str(), std::ios::binary | std::ios::in | std::ios::out);
            if (!public_key_file || !private_key_file)
            {
                std::cerr << "Erro ao abrir os arquivos de chave." << std::endl;
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
    }
}

std::string calculateSHA256Hash(const std::string &data)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data.c_str(), data.size());
    SHA256_Final(hash, &sha256);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }

    return ss.str();
}

std::string get_pdf_hash(std::string pdf_path)
{
    try
    {
        // Abre o pdf
        std::ifstream pdf_file("desligamento_usina.pdf", std::ios::binary);

        if (!pdf_file)
        {
            std::cerr << "Erro ao abrir o arquivo PDF." << std::endl;
        }

        // Lê conteúdo do pdf
        std::ostringstream pdf_data;
        pdf_data << pdf_file.rdbuf();

        pdf_file.close();

        std::string pdf_contents = pdf_data.str();

        // Calcula o hash SHA256 dos dados do PDF
        std::string pdf_hash = calculateSHA256Hash(pdf_contents);

        // std::cout << "Hash SHA-256 do PDF: " << pdf_hash << std::endl;
        return pdf_hash;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Erro: " << e.what() << std::endl;
        return "1";
    }
}

int main(int argc, char **argv)
{
    create_keys();

    std::string pdf_hash = get_pdf_hash("desligamento_usina.pdf");
    std::cout << "Hash SHA-256 do PDF: " << get_pdf_hash("desligamento_usina.pdf") << std::endl;

    try
    {
        // Caminho para arquivo de chave privada
        const char *private_key_path = ".keys/private_key_0.pem";

        // Carrega a chave privada a partir do arquivo .pem usando OpenSSL
        FILE *private_key_file = fopen(private_key_path, "r");
        if (!private_key_file)
        {
            throw std::runtime_error("Erro ao abrir o arquivo de chave privada");
        }

        EVP_PKEY *evp_private_key = PEM_read_PrivateKey(private_key_file, nullptr, nullptr, nullptr);
        fclose(private_key_file);
        if (!evp_private_key)
        {
            throw std::runtime_error("Erro ao carregar a chave privada usando OpenSSL");
        }

        // Chave privada carregada em 'evp_private_key'
        PrivateKey private_key = PrivateKey(evp_private_key);
        std::cout << private_key.getPemEncoded() << std::endl;

        // Libera a memória da chave privada quando não for mais necessária
        EVP_PKEY_free(evp_private_key);

        //
        const char *public_key_path = ".keys/public_key_0.pem";

        // Carrega a chave pública a partir do arquivo .pem usando OpenSSL
        FILE *public_key_file = fopen(public_key_path, "r");
        if (!public_key_file)
        {
            throw std::runtime_error("Erro ao abrir o arquivo de chave privada");
        }

        EVP_PKEY *evp_public_key = PEM_read_PUBKEY(public_key_file, nullptr, nullptr, nullptr);
        fclose(public_key_file);

        if (!evp_public_key)
        {
            throw std::runtime_error("Erro ao carregar a chave privada usando OpenSSL");
        }

        // Chave pública carregada em 'evp_public_key'
        PublicKey public_key = PublicKey(evp_public_key);
        std::cout << public_key.getPemEncoded() << std::endl;

        // Libera a memória da chave pública quando não for mais necessária
        EVP_PKEY_free(evp_public_key);

        ByteArray pdf_hash_data(pdf_hash);
        std::cout << pdf_hash_data.toString() << std::endl;

        // Assina o hash do documento usando a chave privada
        ByteArray assinatura = Signer::sign(private_key, pdf_hash_data, MessageDigest::SHA256);

        // Verificar a assinatura (opcional)
        // Suponha que você já tenha carregado a chave pública correspondente em 'publicKey'
        // PublicKey publicKey = loadPublicKeyFromFile("public_key.pem");
        bool isValid = Signer::verify(public_key, assinatura, pdf_hash_data, MessageDigest::SHA256);
        if (isValid)
        {
            std::cout << "A assinatura é válida." << std::endl;
        }
        else
        {
            std::cout << "A assinatura não é válida." << std::endl;
        }
    }
    catch (AsymmetricKeyException &e)
    {
        std::cerr << "Erro ao assinar ou verificar a assinatura: " << e.getDetails() << std::endl;
        return 1;
    }
    catch (SignerException &e)
    {
        std::cerr << "Erro ao assinar ou verificar a assinatura: " << e.what() << std::endl;
        return 1;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Erro: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
