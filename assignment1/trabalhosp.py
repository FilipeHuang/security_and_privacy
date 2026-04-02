import os
import timeit
import statistics
import hashlib
import math
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa

# Chave AES de 256 bits (32 bytes) e Nonce para o modo CTR
chave = os.urandom(32)
nonce = os.urandom(16)
tamanhos = [8, 64, 512, 4096, 32768, 262144, 2097152]

# Geração de chaves RSA e extração dos parâmetros matemáticos puros (n, e, d)
chave_privada = rsa.generate_private_key(public_exponent=65537, key_size=2048)
n_mod = chave_privada.public_key().public_numbers().n
e_pub = chave_privada.public_key().public_numbers().e
d_priv = chave_privada.private_numbers().d

def gerar_ficheiros():
    for tamanho in tamanhos:
        nome_ficheiro = f"random_{tamanho}.txt"
        with open(nome_ficheiro, "wb") as f: 
            f.write(os.urandom(tamanho))

def tempo_execucao(funcao, dados, repeticoes=100):
    funcao(dados) # Warm-up para evitar cold start
    tempos = timeit.repeat(lambda: funcao(dados), number=1, repeat=repeticoes)
    tempos_us = [t * 1_000_000 for t in tempos] # Conversão direta para microsegundos (us)
    media_us = statistics.mean(tempos_us)
    return media_us, (statistics.stdev(tempos_us) if repeticoes > 1 else 0.0)

def AES_cifra(dados):
    cifra = Cipher(algorithms.AES(chave), modes.CTR(nonce))
    encriptador = cifra.encryptor()
    return encriptador.update(dados) + encriptador.finalize()

def AES_decifra(dados):
    cifra = Cipher(algorithms.AES(chave), modes.CTR(nonce))
    decriptador = cifra.decryptor()
    return decriptador.update(dados) + decriptador.finalize()

# Operação RSA base (Cifra): m^e mod n
def rsa_funcao(r_bytes):
    r_int = int.from_bytes(r_bytes, 'big')
    c_int = pow(r_int, e_pub, n_mod)
    return c_int.to_bytes(256, 'big') 

# Operação RSA inversa (Decifra): c^d mod n
def rsa_inverso(c_bytes):
    c_int = int.from_bytes(c_bytes, 'big')
    r_int = pow(c_int, d_priv, n_mod)
    return r_int.to_bytes(32, 'big')

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def RSA_cifra_custom(m):
    l = 32
    r = os.urandom(32)
    c0 = rsa_funcao(r) # Encapsula a seed aleatória 'r' com o RSA puro
    n_blocos = math.ceil(len(m) / l)
    blocos_cifra = [c0]
    for i in range(n_blocos):
        m_i = m[i*l : (i+1)*l]
        i_bytes = i.to_bytes(4, 'big')
        # Combina a seed 'r' com o índice do bloco e aplica XOR com a mensagem
        h = hashlib.sha256(i_bytes + r).digest()
        c_i = xor_bytes(h[:len(m_i)], m_i)
        blocos_cifra.append(c_i)
    return b''.join(blocos_cifra)

def RSA_decifra_custom(ct):
    l = 32
    # Extrai os primeiros 256 bytes (c0) e recupera a seed 'r' usando a chave privada
    c0 = ct[:256]
    r = rsa_inverso(c0)
    ct_restante = ct[256:]
    n_blocos = math.ceil(len(ct_restante) / l)
    blocos_texto = []
    for i in range(n_blocos):
        c_i = ct_restante[i*l : (i+1)*l]
        i_bytes = i.to_bytes(4, 'big')
        h = hashlib.sha256(i_bytes + r).digest()
        m_i = xor_bytes(h[:len(c_i)], c_i)
        blocos_texto.append(m_i)
    return b''.join(blocos_texto)

def gerador_SHA256(dados):
    digest = hashlib.sha256()
    digest.update(dados)
    return digest.digest()

def executar_benchmarks():
    gerar_ficheiros()
    print("Ficheiros gerados. A iniciar benchmarks...\n")
    
    resultados = {
        "tamanhos": tamanhos,
        "aes_enc": [], "aes_dec": [],
        "rsa_enc": [], "rsa_dec": [],
        "sha": []
    }

    for tamanho in tamanhos:
        with open(f"random_{tamanho}.txt", "rb") as f:
            texto_limpo = f.read()
        
        m_enc_aes, s_enc_aes = tempo_execucao(AES_cifra, texto_limpo)
        resultados["aes_enc"].append(m_enc_aes)
        
        cifra_aes = AES_cifra(texto_limpo)
        m_dec_aes, s_dec_aes = tempo_execucao(AES_decifra, cifra_aes)
        resultados["aes_dec"].append(m_dec_aes)
        
        # Reduzir o número de repetições do RSA para tamanhos gigantes (demora demasiado)
        reps_rsa = 10 if tamanho >= 262144 else 100
        m_enc_rsa, s_enc_rsa = tempo_execucao(RSA_cifra_custom, texto_limpo, repeticoes=reps_rsa)
        resultados["rsa_enc"].append(m_enc_rsa)
        
        cifra_rsa = RSA_cifra_custom(texto_limpo)
        m_dec_rsa, s_dec_rsa = tempo_execucao(RSA_decifra_custom, cifra_rsa, repeticoes=reps_rsa)
        resultados["rsa_dec"].append(m_dec_rsa)
        
        m_sha, s_sha = tempo_execucao(gerador_SHA256, texto_limpo)
        resultados["sha"].append(m_sha)
        
        print(f"--- Tamanho: {tamanho} bytes ---")
        print(f"AES Cifra   : {m_enc_aes:.2f} us (±{s_enc_aes:.2f})")
        print(f"AES Decifra : {m_dec_aes:.2f} us (±{s_dec_aes:.2f})")
        print(f"RSA Cifra   : {m_enc_rsa:.2f} us (±{s_enc_rsa:.2f})")
        print(f"RSA Decifra : {m_dec_rsa:.2f} us (±{s_dec_rsa:.2f})")
        print(f"SHA256      : {m_sha:.2f} us (±{s_sha:.2f})\n")

    return resultados