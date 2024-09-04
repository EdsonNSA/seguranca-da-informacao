from hashlib import sha256
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import base64

# Definição das classes de usuários e permissões
class Usuario:
    def __init__(self, nome_usuario, senha, funcao):
        self.nome_usuario = nome_usuario
        self.senha = sha256(senha.encode()).hexdigest()
        self.funcao = funcao

    def temAcesso(self, acao):
        return acao in self.funcao.permissoes

class Funcao:
    def __init__(self, nome, permissoes):
        self.nome = nome
        self.permissoes = permissoes

class Dados:
    def __init__(self, nome):
        self.nome = nome

# Definindo as permissões para cada papel
funcoesAdmin = Funcao("admin", ["ler", "escrever", "excluir"])
funcoesUsuario = Funcao("usuario", ["ler", "escrever"])
funcoesConvidado = Funcao("convidado", ["ler"])

# Criando recursos
dados = Dados("dados sensíveis")

# Criando usuários
admin = Usuario("admin", "admin", funcoesAdmin)
usuario = Usuario("padrao", "123", funcoesUsuario)
convidado = Usuario("convidado", "convidado", funcoesConvidado)

# Função de autenticação
def autenticar(nome_usuario, senha):
    for u in [admin, usuario, convidado]:
        if u.nome_usuario == nome_usuario and u.senha == sha256(senha.encode()).hexdigest():
            return u
    return None

# Criptografia Simétrica com Fernet
chaveSimetrica = Fernet.generate_key()
cifraSimetrica = Fernet(chaveSimetrica)

def criptografarSimetrico(dados):
    return cifraSimetrica.encrypt(dados.encode()).decode('utf-8')

def descriptografarSimetrico(dadosCriptografados):
    return cifraSimetrica.decrypt(dadosCriptografados.encode('utf-8')).decode('utf-8')

# Criptografia Assimétrica com RSA
def gerar_chaves():
    chave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    chave_publica = chave_privada.public_key()

    chave_privada_pem = chave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    chave_publica_pem = chave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return chave_privada_pem, chave_publica_pem

chave_privada_pem, chave_publica_pem = gerar_chaves()

chave_privada = serialization.load_pem_private_key(
    chave_privada_pem,
    password=None,
)

chave_publica = serialization.load_pem_public_key(
    chave_publica_pem
)

def criptografar_assimetrico(chave_publica, dados):
    dados_bytes = dados.encode('utf-8')
    dados_criptografados = chave_publica.encrypt(
        dados_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(dados_criptografados).decode('utf-8')

def descriptografar_assimetrico(chave_privada, dados_criptografados_base64):
    dados_criptografados_bytes = base64.b64decode(dados_criptografados_base64)
    dados_descriptografados = chave_privada.decrypt(
        dados_criptografados_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return dados_descriptografados.decode('utf-8')

# Integração do controle de acesso com criptografia de dados
def acessar_dados_criptografados(usuario, recurso, acao, criptografia, dados=None):
    if usuario and usuario.temAcesso(acao):
        if acao == "ler":
            if criptografia == "simetrica":
                dadosDescriptografados = descriptografarSimetrico(dados)
            elif criptografia == "assimetrica":
                dadosDescriptografados = descriptografar_assimetrico(chave_privada, dados)
            print(f"usuário {usuario.nome_usuario} leu: {dadosDescriptografados}")
        elif acao == "escrever":
            if criptografia == "simetrica":
                dadosCriptografados = criptografarSimetrico(dados)
            elif criptografia == "assimetrica":
                dadosCriptografados = criptografar_assimetrico(chave_publica, dados)
            print(f"usuário {usuario.nome_usuario} escreveu: {dadosCriptografados}")
        else:
            print(f"ação {acao} não suportada")
    else:
        print(f"acesso negado para {usuario.nome_usuario} para {acao} no {recurso.nome}")

# Interface do terminal
def principal():
    print("[=== sistema de controle de acesso ===]")
    usuarioLogin = input("nome de usuário: ")
    senha = input("senha: ")

    usuarioAutenticado = autenticar(usuarioLogin, senha)

    if not usuarioAutenticado:
        print("usuário ou senha inválidos!")
        return

    print(f"bem-vindo, {usuarioAutenticado.nome_usuario}!")

    while True:
        print("\nescolha uma ação:")
        print("1. ler dados sensíveis")
        print("2. escrever dados sensíveis")
        print("3. sair")

        escolha = input("digite o número da ação: ")

        if escolha == "1":
            criptografia = input("informe o tipo de criptografia usada (simetrica/assimetrica): ").lower()
            dadosCriptografados = input("informe os dados criptografados para ler (ou deixe em branco para usar exemplo): ")
            if not dadosCriptografados:
                if criptografia == "simétrica":
                    dadosCriptografados = criptografarSimetrico("informação secreta")
                elif criptografia == "assimétrica":
                    dadosCriptografados = criptografar_assimetrico(chave_publica, "informação secreta")
            acessar_dados_criptografados(usuarioAutenticado, dados, "ler", criptografia, dadosCriptografados)

        elif escolha == "2":
            dados_para_criptografar = input("digite os dados que deseja criptografar e armazenar: ")
            criptografia = input("escolha o tipo de criptografia (simetrica/assimetrica): ").lower()
            acessar_dados_criptografados(usuarioAutenticado, dados, "escrever", criptografia, dados_para_criptografar)

        elif escolha == "3":
            print("saindo do sistema. até mais!")
            break

        else:
            print("escolha inválida, tente novamente.")

if __name__ == "__main__":
    principal()
