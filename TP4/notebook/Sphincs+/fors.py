from sphincs_aux import *

# FORS  few-time signature scheme

# Este código implementa a classe Fors (Few-Time Signature Scheme), que é um esquema de assinatura 
# criptográfica baseado em árvores de Merkle chamadas de FORS (Few-time Signature Scheme).


# A classe Fors possui estes métodos:

#     "auths_from_sig_fors" recebe uma assinatura sig e retorna uma lista com as autenticações 
# correspondentes.

#     "fors_sk_gen" gera a chave secreta (secret key) para uma árvore FORS específica, com base em 
# uma seed secreta, um endereço ADRS e um índice.

#     "fors_treehash" calcula o nó raiz de uma árvore FORS, com base em uma seed secreta, um 
# índice inicial, uma altura alvo, uma seed pública e um endereço ADRS.

#     "fors_pk_gen" gera a chave pública (public key) para o esquema FORS, com base em uma seed 
# secreta, uma seed pública e um endereço ADRS.

#     "fors_sign" assina uma mensagem usando o esquema FORS, com base em uma mensagem, uma seed 
# secreta, uma seed pública e um endereço ADRS.

#     "fors_pk_from_sig" verifica a assinatura e recupera a chave pública correspondente, com base 
# em uma assinatura sig, uma mensagem, uma seed pública e um endereço ADRS.

class Fors:
    def __init__(self):
        
        self._n = 16 # tamanho em bytes do nó da árvore
        self._k = 10 # número de árvores FORS
        self._a = 15 # 
        self._t = 2 ** self._a

    def auths_from_sig_fors(self, sig):
        sigs = []
        for i in range(self._k):
            sigs.append([])
            sigs[i].append(sig[(self._a + 1) * i])
            sigs[i].append(sig[((self._a + 1) * i + 1):((self._a + 1) * (i + 1))])

        return sigs

    def fors_sk_gen(self, secret_seed, adrs: ADRS, idx):
        adrs.set_tree_height(0)
        adrs.set_tree_index(idx)
        sk = prf(secret_seed, adrs.copy(), self._n)

        return sk

    # Input: Secret seed SK.seed, start index s, target node height z, public seed PK.seed, address ADRS
    # Output: n-byte root node - top node on Stack
    def fors_treehash(self, secret_seed, s, z, public_seed, adrs):
        if s % (1 << z) != 0:
            return -1

        stack = []

        for i in range(2 ** z):
            adrs.set_tree_height(0)
            adrs.set_tree_index(s + i)
            sk = prf(secret_seed, adrs.copy(), self._n)
            node = hash_(public_seed, adrs.copy(), sk, self._n)

            adrs.set_tree_height(1)
            adrs.set_tree_index(s + i)
            if len(stack) > 0:
                while stack[len(stack) - 1]['height'] == adrs.get_tree_height():
                    adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
                    node = hash_(public_seed, adrs.copy(), stack.pop()['node'] + node, self._n)

                    adrs.set_tree_height(adrs.get_tree_height() + 1)

                    if len(stack) <= 0:
                        break
            stack.append({'node': node, 'height': adrs.get_tree_height()})

        return stack.pop()['node']

    # Input: Secret seed SK.seed, public seed PK.seed, address ADRS
    # Output: FORS public key PK
    def fors_pk_gen(self, secret_seed, public_seed, adrs: ADRS):
        fors_pk_adrs = adrs.copy()

        root = bytes()
        for i in range(0, self._k):
            root += self.fors_treehash(secret_seed, i * self._t, self._a, public_seed, adrs)

        fors_pk_adrs.set_type(ADRS.FORS_ROOTS)
        fors_pk_adrs.set_key_pair_address(adrs.get_key_pair_address())
        pk = hash_(public_seed, fors_pk_adrs, root, self._n)
        return pk

    # Input: Bit string M, secret seed SK.seed, address ADRS, public seed PK.seed
    # Output: FORS signature SIG_FORS
    def fors_sign(self, m, secret_seed, public_seed, adrs):
        m_int = int.from_bytes(m, 'big')
        sig_fors = []

        for i in range(self._k):
            idx = (m_int >> (self._k - 1 - i) * self._a) % self._t

            adrs.set_tree_height(0)
            adrs.set_tree_index(i * self._t + idx)
            sig_fors += [prf(secret_seed, adrs.copy(), self._n)]

            auth = []

            for j in range(self._a):
                s = math.floor(idx // 2 ** j)
                if s % 2 == 1:  # XORING idx/ 2**j with 1
                    s -= 1
                else:
                    s += 1

                auth += [self.fors_treehash(secret_seed, i * self._t + s * 2 ** j, j, public_seed, adrs.copy())]

            sig_fors += auth

        return sig_fors

    # Input: FORS signature SIG_FORS, (k lg t)-bit string M, public seed PK.seed, address ADRS
    # Output: FORS public key
    def fors_pk_from_sig(self, sig_fors, m, public_seed, adrs: ADRS):
        m_int = int.from_bytes(m, 'big')

        sigs = self.auths_from_sig_fors(sig_fors)
        root = bytes()

        for i in range(self._k):
            idx = (m_int >> (self._k - 1 - i) * self._a) % self._t

            sk = sigs[i][0]
            adrs.set_tree_height(0)
            adrs.set_tree_index(i * self._t + idx)
            node_0 = hash_(public_seed, adrs.copy(), sk, self._n)
            node_1 = 0

            auth = sigs[i][1]
            adrs.set_tree_index(i * self._t + idx)  # Really Useful?

            for j in range(self._a):
                adrs.set_tree_height(j + 1)

                if math.floor(idx / 2 ** j) % 2 == 0:
                    adrs.set_tree_index(adrs.get_tree_index() // 2)
                    node_1 = hash_(public_seed, adrs.copy(), node_0 + auth[j], self._n)
                else:
                    adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
                    node_1 = hash_(public_seed, adrs.copy(), auth[j] + node_0, self._n)

                node_0 = node_1

            root += node_0

        fors_pk_adrs = adrs.copy()
        fors_pk_adrs.set_type(ADRS.FORS_ROOTS)
        fors_pk_adrs.set_key_pair_address(adrs.get_key_pair_address())

        pk = hash_(public_seed, fors_pk_adrs, root, self._n)
        return pk