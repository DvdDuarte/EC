# Imports
import os
import random
import asyncio
import nest_asyncio
from pickle import dumps, loads
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature

nest_asyncio.apply()

def gerarChaves():
    cifraChavePrivada = ec.generate_private_key(ec.SECP384R1())
    cifraChavePublica = cifraChavePrivada.public_key()
    
    macChavePrivada = ec.generate_private_key(ec.SECP384R1())
    macChavePublica = macChavePrivada.public_key()

    mensagem = {'sms_cipher': cifraChavePublica.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo), 
                'sms_mac': macChavePublica.public_bytes(encoding=serialization.Encoding.PEM, format= serialization.PublicFormat.SubjectPublicKeyInfo)}

    return dumps(mensagem), cifraChavePrivada, macChavePrivada

def gerarAssinatura(sms, chavePrivada):
    
    assinatura = chavePrivada.sign(sms, ec.ECDSA(hashes.SHA256()))
    
    smsFinal = {'message': sms, 
                'signature': assinatura, 
                'pub_key': chavePrivada.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)}
    
    return smsFinal

def gerarChavePartilhada(sms, cifraChavePrivada, macChavePrivada):
    cifraChavePublica = load_pem_public_key(sms['sms_cipher'])
    macChavePublica = load_pem_public_key(sms['sms_mac'])

    cifraChavePartilhada = cifraChavePrivada.exchange(ec.ECDH(), cifraChavePublica)
    macChavePartilhada = macChavePrivada.exchange(ec.ECDH(), macChavePublica)

    return cifraChavePartilhada, macChavePartilhada

def gerarMac(chave, crypto):
    h = hmac.HMAC(chave, hashes.SHA3_256())
    h.update(crypto)
    return h.finalize()

def cifrar(plaintext, cifraChave, macChave):
    
    xof = hashes.Hash(hashes.SHA3_256())
    nonce = xof.finalize()
    additionalData = os.urandom(16)
    
    cifra = AESGCM(cifraChave)
    print("CIFRA")
    ciphertext = cifra.encrypt(nonce, dumps(plaintext), additionalData)
    print("Cifrado")

    sms = {'nounce': nounce,
           'cipher': ciphertext}

    # 'tag': encryptor.tag,
    
    chaveMac = gerarMac(macChave, dumps(sms))
    
    print(gerarMac)
    
    return {'message': sms, 'tag': chaveMac, 'associated_data': additionalData}

async def decifrar(ciphertext, cifraChave, macChave):
    texto = ciphertext['message']
    hmac_key = ciphertext['tag']

    macDestino = gerarMac(macChave, dumps(texto))

    if hmac_key != macDestino:
        return 'ERRO - MAC não é igual'

    xof = hashes.Hash(hashes.SHA3_256())
    xof.update(b'nonce generator')
    nonce = xof.finalize()

    cifra = Cipher(algorithms.AES(cifraChave), modes.GCM(nonce, texto['tag'])) 
    decryptor = cifra.decryptor()

    decryptor.authenticate_additional_data(texto['associated_data'])

    plaintext = decryptor.update(texto['cipher']) + decryptor.finalize()

    return plaintext.decode()

async def emitter(queue, plaintext):
    sms, cifraChavePrivada, macChavePrivada = gerarChaves()
    assinatura = gerarAssinatura(sms, cifraChavePrivada)
    
    print("E: Enviar Assinatura...") 
    await asyncio.sleep(random.random())
    await queue.put(assinatura)
    print("E: Assinatura Enviada")
    await asyncio.sleep(random.random())
    
    # sms = receber sms do outro lado
    print("E: A Receber Assinatura...") 
    chavesRecetor = await queue.get()
    print("E: Assinatura Recebida")
    
    if chavesRecetor is None:
        print("ERRO - MENSAGEM VAZIA")
    
    ecdsaPublico = load_pem_public_key(chavesRecetor['pub_key'])
    
    try:
        ecdsaPublico.verify(chavesRecetor['signature'], chavesRecetor['message'], ec.ECDSA(hashes.SHA256()))
        pacoteSMS = loads(chavesRecetor['message'])
        cifraChavePartilhada, macChavePartilhada = gerarChavePartilhada(pacoteSMS, cifraChavePrivada, macChavePrivada)
        
        hmacChave = gerarMac(macChavePartilhada, macChavePartilhada)
        mensagem = cifrar(plaintext, cifraChavePartilhada, macChavePartilhada)
        print("E: Mensagem cifrada")
        
        mensagem['hmac_key'] = hmacChave
        mensagem['associated_data'] = dadosAssociados
        
        # enviar mensagem
        print("E: Enviar Mensagem...")
        await asyncio.sleep(random.random())
        await queue.put(mensagem)
        print("E: Mensagem Enviada")
        await asyncio.sleep(random.random())
        
    except InvalidSignature:
        print("ERRO: Mensagem não autenticada")
        
async def receiver(queue):
    
    pkg, cifraChavePrivada, macChavePrivada = gerarChaves()
    assinatura = gerarAssinatura(pkg, cifraChavePrivada)
    
    print("R: Receber Assinatura")
    assinaturaEmissor = await queue.get()
    print("R: Assinatura Recebida")
    
    ecdsaPublico = load_pem_public_key(assinaturaEmissor['pub_key'])
    
    try:
        ecdsaPublico.verify(assinaturaEmissor['signature'],assinaturaEmissor['message'], ec.ECDSA(hashes.SHA256()))
        #geração das chaves partilhadas
        pkg_msg = loads(assinaturaEmissor['message'])
        cifraChavePartilhada, macChavePartilhada = gerarChavePartilhada(pkg_msg,cifraChavePrivada,macChavePrivada)
        
        # enviar finalPkg 
        print("R: Enviar Assinatura...")
        await asyncio.sleep(random.random())
        await queue.put(assinatura)
        print("R: Assinatura Enviada")
        await asyncio.sleep(random.random())
        
        print("R: Receber Mensagem...")
        message = await queue.get()
        print("R: Mensagem Recebida")
        
        print(message)
        
        hmac_key = message['hmac_key']
        associatedData = message['associated_data']
        
        #verificar o código de autenticação
        if hmac_key == gerarMac(sharedKey_mac,sharedKey_mac):
        #decifrar a mensagem
            final_message = decifrar(message, sharedKey_cipher, sharedKey_mac,associatedData)
        else:
            print('ERRO - Chaves diferentes em uso.')
    except InvalidSignature:
        print("ERRO: A mensagem não é autenticada.")

def main():
    
    plaintext = 'Emissor -> Recetor: Estruturas Criptograficas'
    
    print("Plaintext: " + plaintext)
    
    loop = asyncio.get_event_loop()
    queue = asyncio.Queue(10)
    asyncio.ensure_future(emitter(queue, plaintext), loop=loop)
    loop.run_until_complete(receiver(queue))

main()