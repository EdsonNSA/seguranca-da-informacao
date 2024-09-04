from hashlib import sha256  # importa a função de hash sha256 para a segurança das senhas
from cryptography.fernet import Fernet  # importa a classe fernet para criptografia simétrica
import rsa  # importa a biblioteca rsa para criptografia assimétrica

# definição das classes de usuários e permissões
class Usuario:
    def __init__(self, nomeUsuario, senha, funcao):
        self.nome_usuario = nome_usuario  # define o nome de usuário
        self.senha = sha256(senha.encode()).hexdigest()  # criptografa a senha usando sha-256
        self.funcao = funcao  # atribui a função do usuário (admin, usuário, convidado)

    def temAcesso(self, acao):
        return acao in self.funcao.permissoes  # verifica se o usuário tem permissão para realizar uma ação

class Funcao:
    def __init__(self, nome, permissoes):
        self.nome = nome  # define o nome correspondente à função
        self.permissoes = permissoes  # define as permissões associadas a esse nome

class Dados:
    def __init__(self, nome):
        self.nome = nome  # define o nome do dado 

# definindo as permissões para cada papel
funcoesAdmin = Funcao("admin", ["ler", "escrever", "excluir"])  # papel admin com permissões de leitura, escrita e exclusão
funcoesUsuario = Funcao("usuario", ["ler", "escrever"])  # papel usuário com permissões de leitura e escrita
funcoesConvidado = Funcao("convidado", ["ler"])  # papel convidado com permissão apenas de leitura

# criando recursos
dados = Dados("dados sensíveis")  # define o recurso "dados sensíveis"

# criando usuários
admin = Usuario("admin", "admin", funcoesAdmin)  # cria o usuário admin com seu papel
usuario = Usuario("padrao", "123", funcoesUsuario)  # cria o usuário padrão com seu papel
convidado = Usuario("convidado", "convidado", funcoesConvidado)  # cria o usuário convidado com seu papel

# função de autenticação
def autenticar(nome_Usuario, senha):
    # verifica se o nome de usuário e senha são válidos para algum usuário
    for u in [admin, usuario, convidado]:
        if u.nome_Usuario == nome_Usuario and u.senha == sha256(senha.encode()).hexdigest():
            return u  # retorna o usuário autenticado
    return None  # retorna none se a autenticação falhar

# criptografia simétrica com aes (via fernet)
chaveSimetrica = Fernet.generate_key()  # gera uma chave simétrica para criptografia
cifraSimetrica = Fernet(chaveSimetrica)  # cria um objeto fernet para criptografar e descriptografar

# funções de criptografia e descriptografia simétrica
def criptografarSimetrico(dados):
    return cifraSimetrica.encrypt(dados.encode()).decode('utf-8')  # criptografa os dados e converte para string
def descriptografarSimetrico(dadosCriptografados):
    return cifraSimetrica.decrypt(dadosCriptografados.encode('utf-8')).decode('utf-8')  # descriptografa os dados e converte para string

# integração do controle de acesso com criptografia de dados
def acessar_dados_criptografados_simetricos(usuario, recurso, acao, dados=None):
    # verifica se o usuário tem permissão para realizar a ação no recurso
    if usuario and usuario.temAcesso(acao):
        if acao == "ler":
            dadosDescriptografados = descriptografarSimetrico(dados)  # descriptografa os dados
            print(f"usuário {usuario.nome_Usuario} leu: {dadosDescriptografados}")  # exibe os dados descriptografados
        elif acao == "escrever":
            dadosCriptografados = criptografarSimetrico(dados)  # criptografa os dados
            print(f"usuário {usuario.nome_Usuario} escreveu: {dadosCriptografados}")  # exibe os dados criptografados
        else:
            print(f"ação {acao} não suportada")  # ação não suportada
    else:
        print(f"acesso negado para {usuario.nome_Usuario} para {acao} no {recurso.nome}")  # acesso negado

# função de criptografia com dados assimétricos 


# interface do terminal
def principal():
    print("[=== sistema de controle de acesso ===]")
    usuarioLogin = input("nome de usuário: ")  # solicita o nome de usuário
    senha = input("senha: ")  # solicita a senha
    
    usuarioAutenticado = autenticar(usuarioLogin, senha)  # tenta autenticar o usuário
    
    if not usuarioAutenticado:
        print("usuário ou senha inválidos!")  # mensagem de erro se a autenticação falhar
        return
    
    print(f"bem-vindo, {usuarioAutenticado.nome_usuario}!")  # mensagem de boas-vindas
    
    while True:
        print("\nescolha uma ação:")
        print("1. ler dados sensíveis")
        print("2. escrever dados sensíveis")
        print("3. sair")
        
        escolha = input("digite o número da ação: ")  # solicita ao usuário para escolher uma ação
        
        if escolha == "1":
            dadosCriptografados = input("informe os dados criptografados para ler (ou deixe em branco para usar exemplo): ")
            if not dadosCriptografados:
                dadosCriptografados = criptografarSimetrico("informação secreta")  # exemplo de dado criptografado
            acessar_dados_criptografados_simetricos(usuarioLogin, dados, "ler", dadosCriptografados)  # lê os dados criptografados
        
        elif escolha == "2":
            dados_para_criptografar = input("digite os dados que deseja criptografar e armazenar: ")
            acessar_dados_criptografados_simetricos(usuarioLogin, dados, "escrever", dados_para_criptografar)  # escreve os dados criptografados
        
        elif escolha == "3":
            print("saindo do sistema. até mais!")  # mensagem de saída
            break  # sai do loop e termina o programa
        
        else:
            print("escolha inválida, tente novamente.")  # mensagem de erro para escolha inválida

if __name__ == "__main__":
    principal()  # executa a função principal


