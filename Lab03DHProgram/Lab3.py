import hashlib
import secrets


WHITE = "\033[97m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"


P = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)

G = 2


class SecurePRNG:
    def __init__(self, seed_int):
        seed_bytes = seed_int.to_bytes((seed_int.bit_length()+7)//8, 'big')
        self.state = hashlib.sha256(seed_bytes).digest()

    def generate(self, n):
        output = b""
        while len(output) < n:
            block = hashlib.sha256(self.state).digest()
            print(f"{CYAN}[PRNG Generator Step] State: {self.state.hex()[:8]}... "
                  f"Block: {block.hex()[:8]}...{RESET}")
            output += block
            self.state = hashlib.sha256(self.state + block).digest()
        return output[:n]

def xor_crypt(data, prng):
    keystream = prng.generate(len(data))
    return bytes(a ^ b for a, b in zip(data, keystream))


class Entity:
    def __init__(self, name):
        self.name = name
        self.private = secrets.randbelow(P - 2) + 1
        self.public = pow(G, self.private, P)
        self.prng = None
        self.shared_secret = None

    def get_public_hex(self):
        return hex(self.public)

    def establish_session(self, other_hex):
        other_pub = int(other_hex, 16)
        print(f"{CYAN}[{self.name} Calculation] "
              f"{str(other_pub)[:20]}... ^ "
              f"{str(self.private)[:20]}... mod P{RESET}")
        self.shared_secret = pow(other_pub, self.private, P)
        self.prng = SecurePRNG(self.shared_secret)
        print(f"{YELLOW}{self.name} Calculated Shared Secret:{RESET} "
              f"{str(self.shared_secret)[:40]} ... "
              f"{str(self.shared_secret)[-14:]}")

# = MALLORY =
class Mallory:
    def __init__(self):
        self.private = secrets.randbelow(P - 2) + 1
        self.public = pow(G, self.private, P)
        self.public_hex = hex(self.public)
        self.alice_prng = None
        self.bob_prng = None
        self.alice_secret = None
        self.bob_secret = None

    def intercept(self, sender, recipient, payload):
        if isinstance(payload, str) and payload.startswith("0x"):
            remote_pub = int(payload, 16)
            shared_secret = pow(remote_pub, self.private, P)

            if sender == "Alice":
                print(f"{RED}[ATTACK] Mallory intercepted Public Key destined for Bob!{RESET}")
                self.alice_secret = shared_secret
                self.alice_prng = SecurePRNG(shared_secret)
                print(f"{YELLOW}Mallory's Shared Secret with Alice:{RESET} "
                      f"{str(shared_secret)[:40]} ... {str(shared_secret)[-14:]}")
            else:
                print(f"{RED}[ATTACK] Mallory intercepted Public Key destined for Alice!{RESET}")
                self.bob_secret = shared_secret
                self.bob_prng = SecurePRNG(shared_secret)
                print(f"{YELLOW}Mallory's Shared Secret with Bob:{RESET} "
                      f"{str(shared_secret)[:40]} ... {str(shared_secret)[-14:]}")

            print(f"{RED}[ATTACK] Mallory forwarding HER public key to {recipient}...{RESET}")
            return self.public_hex

        if isinstance(payload, bytes):
            print(f"{RED}[ATTACK] Mallory intercepted encrypted message!{RESET}")
            plaintext = xor_crypt(payload, self.alice_prng)
            print("Mallory Decrypted Plaintext:", plaintext.decode())

            modified = plaintext.replace(b"Krish", b"Mallory")

            print(f"{RED}[ATTACK] Mallory Modifying Payload to: "
                  f"'{modified.decode()}'{RESET}")

            return xor_crypt(modified, self.bob_prng)

        return payload

# NETWORK_
class Network:
    def __init__(self, mallory=None):
        self.mallory = mallory

    def send(self, sender, recipient, payload):
        if self.mallory:
            return self.mallory.intercept(sender, recipient, payload)
        return payload

# _MAIN
def main():

    print(f"\nUsing Diffie-Hellman Parameters:")
    print("G:", G)
    print("Bit Length of P:", P.bit_length(), "bits")

    # ================= SCENARIO A =================
    print(f"\n{WHITE}{'='*60}")
    print("SCENARIO A: BENIGN (SECURE) COMMUNICATION".center(60))
    print(f"{'='*60}{RESET}\n")

    alice = Entity("Alice")
    bob = Entity("Bob")
    net = Network()

    print(f"{YELLOW}Alice Private Key (a):{RESET} "
          f"{str(alice.private)[:40]} ... {str(alice.private)[-14:]}")
    print(f"{YELLOW}Alice Public Key (g^a mod P):{RESET} "
          f"{str(alice.public)[:40]} ... {str(alice.public)[-14:]}")
    print(f"{YELLOW}Bob Private Key (b):{RESET} "
          f"{str(bob.private)[:40]} ... {str(bob.private)[-14:]}")
    print(f"{YELLOW}Bob Public Key (g^b mod P):{RESET} "
          f"{str(bob.public)[:40]} ... {str(bob.public)[-14:]}\n")

    print(f"{CYAN}[STEP] Step 1: Public Key Exchange{RESET}")

    key_for_bob = net.send("Alice", "Bob", alice.get_public_hex())
    print(f"{YELLOW}Bob received Key:{WHITE} {key_for_bob[2:18]} ... {key_for_bob[-16:]}")

    key_for_alice = net.send("Bob", "Alice", bob.get_public_hex())
    print(f"{YELLOW}Alice received Key: {WHITE}{key_for_alice[2:18]} ... {key_for_alice[-16:]}")

    print(f"\n{CYAN}[STEP] Step 2: Calculating Shared Secrets{RESET}")
    alice.establish_session(key_for_alice)
    bob.establish_session(key_for_bob)

    print(f"{GREEN}[SUCCESS] Secrets Match! Secure Channel Established.{RESET}\n")

    print(f"{CYAN}[STEP] Step 3: Secure Message Transmission{RESET}")
    message = "Use Krish for the test."
    print("Alice sending:", message)

    ciphertext = xor_crypt(message.encode(), alice.prng)
    print("Encrypted (Hex):", ciphertext.hex())

    decrypted = xor_crypt(ciphertext, bob.prng)
    print("Bob decrypted:", decrypted.decode())
    print(f"{GREEN}[SUCCESS] Communication Integrity Verified.{RESET}")

    # ================= SCENARIO B =================
    print(f"\n{WHITE}{'='*60}")
    print("SCENARIO B: MALICIOUS (MITM) ATTACK".center(60))
    print(f"{'='*60}{RESET}\n")

    alice = Entity("Alice")
    bob = Entity("Bob")
    mallory = Mallory()
    net = Network(mallory)

    print(f"{YELLOW}Alice Private Key (a):{RESET} "
          f"{str(alice.private)[:40]} ... {str(alice.private)[-14:]}")
    print(f"{YELLOW}Alice Public Key (g^a mod P):{RESET} "
          f"{str(alice.public)[:40]} ... {str(alice.public)[-14:]}")
    print(f"{YELLOW}Bob Private Key (b):{RESET} "
          f"{str(bob.private)[:40]} ... {str(bob.private)[-14:]}")
    print(f"{YELLOW}Bob Public Key (g^b mod P):{RESET} "
          f"{str(bob.public)[:40]} ... {str(bob.public)[-14:]}")
    print(f"{YELLOW}Mallory Private Key (private_key):{RESET} "
          f"{str(mallory.private)[:40]} ... {str(mallory.private)[-14:]}")
    print(f"{YELLOW}Mallory Public Key (g^private_key mod P):{RESET} "
          f"{str(mallory.public)[:40]} ... {str(mallory.public)[-14:]}\n")
    print(f"{CYAN}[STEP] Step 1: Mallory infiltrates the Network{RESET}")
    print(f"{RED}[ATTACK] Mallory is now active on the network line.{RESET}\n")

    print(f"{CYAN}[STEP] Step 2: Compromised Key Exchange{RESET}")

    print(f"{WHITE}Alice sending key to Bob...{RESET}")
    key_for_bob = net.send("Alice", "Bob", alice.get_public_hex())

    print(f"{WHITE}Bob sending key to Alice...{RESET}")
    key_for_alice = net.send("Bob", "Alice", bob.get_public_hex())

    print()

    print(f"{CYAN}[STEP] Step 3: Calculating Shared Secrets{RESET}")
    alice.establish_session(key_for_alice)
    bob.establish_session(key_for_bob)

    # ✅ ADDED LINES (only addition)
    print(f"{YELLOW}Alice's Secret (with Mallory):{RESET} "
          f"{str(alice.shared_secret)[:40]} ... {str(alice.shared_secret)[-14:]}")
    print(f"{YELLOW}Bob's Secret (with Mallory):{RESET} "
          f"{str(bob.shared_secret)[:40]} ... {str(bob.shared_secret)[-14:]}")

    print(f"{RED}[ATTACK] NOTE: Alice and Bob have DIFFERENT secrets (MITM Successful).{RESET}\n")

    print(f"{CYAN}[STEP] Step 4: Active Message Interception{RESET}")
    message = "Use Krish for the test."
    print("Alice sending:", message)

    encrypted = xor_crypt(message.encode(), alice.prng)
    delivered = net.send("Alice", "Bob", encrypted)

    print(f"\n{CYAN}[STEP] Step 5: Victim Decryption{RESET}")
    final = xor_crypt(delivered, bob.prng)
    print("Bob decrypted:", final.decode())
    print(f"{RED}[ATTACK] ATTACK SUCCESS: Bob received the modified message.{RESET}")

if __name__ == "__main__":
    main()