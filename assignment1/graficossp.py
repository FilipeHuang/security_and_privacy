import matplotlib.pyplot as plt
import trabalhosp

def gerar_graficos():
    dados = trabalhosp.executar_benchmarks()
    
    tamanhos = dados["tamanhos"]
    
    plt.figure(figsize=(10, 6))

    plt.plot(tamanhos, dados["aes_enc"], marker='o', label='AES Cifra')
    plt.plot(tamanhos, dados["aes_dec"], marker='o', label='AES Decifra')
    plt.plot(tamanhos, dados["rsa_enc"], marker='s', label='RSA Cifra')
    plt.plot(tamanhos, dados["rsa_dec"], marker='s', label='RSA Decifra')
    plt.plot(tamanhos, dados["sha"], marker='^', label='SHA-256')

    # Configuração dos eixos
    plt.xscale('log', base=2)
    plt.yscale('log')
    plt.xlabel('Tamanho do Ficheiro (Bytes)')
    plt.ylabel('Tempo (us)')
    
    plt.title('Desempenho de Mecanismos Criptográficos')
    plt.grid(True, which="both", ls="--", alpha=0.5)
    plt.legend()
    
    # print("A abrir janela com o gráfico...")
    # plt.show()
    plt.savefig("grafico.png", dpi=300)
    print("Gráfico guardado")

if __name__ == "__main__":
    gerar_graficos()
