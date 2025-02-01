#!/usr/bin/env python3
from utils import H, cns_encrypt, cns_decrypt


class User:
    def __init__(self, username, user_id=None, key_server=None):
        self.username = username
        self.user_id = user_id
        self.key = None
    
    def __str__(self,):
        return self.username
    
    def requestS(self, ):
        # TODO: Implement the protocol
        pass
    
    def listenA(self, ):
        pass

    def listenB(self, ):
        # TODO: Implement the protocol
        pass

    def listenS(self, ):
        # TODO: Implement the protocol
        pass

    def forwardA(self, ):
        pass

    def forwardB(self, ):
        # TODO: Implement the protocol
        pass

    def respondA(self, ):
        pass

    def respondB(self, ):
        # TODO: Implement the protocol
        pass

    def send_msg_A(self, ):
        pass

    def send_msg_B(self, ):
        pass

    def receive_msg_A(self, ):
        pass

    def receive_msg_B(self, ):
        # TODO: Implement the protocol
        pass

    def _encrypt_msg(self, key: bytes, msg: bytes) -> bytes:
        return cns_encrypt(key, msg)

    def _decrypt_msg(self, key: bytes, encrypted_msg: bytes) -> bytes:
        return cns_decrypt(key, encrypted_msg)

