import random
import base64
import hashlib

FIRST_PRIMES_LIST = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
    31, 37, 41, 43, 47, 53, 59, 61, 67,
    71, 73, 79, 83, 89, 97, 101, 103, 107,
    109, 113, 127, 131, 137, 139, 149, 151,
    157, 163, 167, 173, 179, 181, 191, 193,
    197, 199, 211, 223, 227, 229, 233, 239,
    241, 251, 257, 263, 269, 271, 277, 281,
    283, 293, 307, 311, 313, 317, 331, 337,
    347, 349
]
NUMBER_OF_RABIN_TRAILS = 20
DEFAULT_PRIME_BITS = 1024
MAX_PRIVATE_VALUE = 1000
MAX_NTH_E_CANDIDATE = 20

def __n_bit_random(n: int) -> int:
    return random.randrange(2**(n-1)+1, 2**n - 1)

def __get_low_level_prime_candidate(n: int) -> int:
    while True:
        prime_candidate = __n_bit_random(n)
        for divisor in FIRST_PRIMES_LIST:
            if prime_candidate % divisor == 0 and divisor**2 <= prime_candidate:
                break
        else:
            return prime_candidate

def __is_miller_rabin_passed(prime_candidate: int) -> bool:
    max_divisions_by_two = 0
    ec = prime_candidate - 1
    while ec % 2 == 0:
        ec >>= 1
        max_divisions_by_two += 1
    assert(2**max_divisions_by_two * ec == prime_candidate-1)

    def trial_composite(round_tester):
        if pow(round_tester, ec, prime_candidate) == 1:
            return False
        for i in range(max_divisions_by_two):
            if pow(round_tester, 2**i * ec, prime_candidate) == prime_candidate-1:
                return False
        return True

    for i in range(NUMBER_OF_RABIN_TRAILS):
        round_tester = random.randrange(2, prime_candidate)
        if trial_composite(round_tester):
            return False
    return True

def get_random_primos(bits: int = DEFAULT_PRIME_BITS) -> int:
    while True:
        prime_candidate = __get_low_level_prime_candidate(bits)
        if not __is_miller_rabin_passed(prime_candidate):
            continue
        else:
            break
    return prime_candidate

def __computes_value_to_send(alpha: int, private: int, p: int) -> int:
    return pow(alpha, private, p)

def __calculate_psk(received_value: int, private: int, p: int) -> int:
    return pow(received_value, private, p)

def get_value_to_send(alpha: int, p: int) -> tuple[int, int]:
    private = random.randint(2, MAX_PRIVATE_VALUE)
    to_send = __computes_value_to_send(alpha, private, p)
    return private, to_send

def generate_psk(received_value: int, private: int, p: int) -> int:
    psk = __calculate_psk(received_value, private, p)
    return psk

def __mdc(a: int, b: int) -> int:
    if not b:
        return a
    return __mdc(b, a % b)

def __select_e(phi: int, n: int, e_candidate: int = 2, nth_candidate: int = 1) -> int:
    if n % e_candidate == 0 or __mdc(phi, e_candidate) != 1:
        return __select_e(phi, n, e_candidate + 1, nth_candidate)
    return e_candidate if nth_candidate == 1 else __select_e(phi, n, e_candidate + 1, nth_candidate - 1)

def __get_d(e: int, phi: int, k: int = 2) -> int:
    d_candidate = (phi * k + 1) // e
    remainder = (phi * k + 1) % e
    if not remainder == 0:
        return __get_d(e, phi, k + 1)
    return int(d_candidate)

def generate_keys() -> tuple[tuple[int, int], tuple[int, int]]:
    p, q = [get_random_primos() for i in range(2)]
    n = p * q
    phi = (p - 1) * (q - 1)
    e = __select_e(phi, n, nth_candidate=random.randint(1, MAX_NTH_E_CANDIDATE))
    d = __get_d(e, phi)
    puk = (e, n)
    prk = (d, n)
    return puk, prk

def __get_number_of_digits(n: int) -> int:
    if n != 0:
        return __get_number_of_digits(n // 10) + 1
    return 0

def __zero_fill_int_as_str(n: int, fill: int) -> str:
    total_zeros = fill - __get_number_of_digits(n)
    zeros = "".join(["0" for i in range(total_zeros)])
    return zeros + str(n)

def encrypt(message: str, puk: tuple[int, int]) -> str:
    e, n = puk
    digits = __get_number_of_digits(n)
    encrypted_bytes = list()
    for byte in base64.b64encode(message.encode('utf-8')):
        encrypted_bytes.append(__zero_fill_int_as_str(pow(byte, e, n), digits))
    encrypted = "".join(encrypted_bytes)
    return encrypted

def decrypt(message: str, prk: tuple[int, int]) -> str:
    d, n = prk
    digits = __get_number_of_digits(n)
    decrypted_bytes = list()
    for i in range(0, len(message), digits):
        byte = int(message[i:i + digits])
        decrypted_bytes.append(pow(byte, d, n))
    decrypted = base64.b64decode(bytearray(decrypted_bytes) + b"==").decode('utf-8')
    return decrypted


def sha256_hash(message: str) -> str:
    """Gera o hash SHA-256 da mensagem fornecida."""
    sha_signature = hashlib.sha256(message.encode()).hexdigest()
    return sha_signature

def sha256_verify(message: str, hash_value: str) -> bool:
    """Verifica se o hash da mensagem fornecida corresponde ao hash fornecido."""
    return sha256_hash(message) == hash_value


if __name__ == "__main__":
    
    alpha, p = [get_random_primos() for i in range(2)]
    private_a, a_to_send = get_value_to_send(alpha, p)
    private_b, b_to_send = get_value_to_send(alpha, p)
    psk_a = generate_psk(b_to_send, private_a, p)
    psk_b = generate_psk(a_to_send, private_b, p)
    print("Chaves geradas são iguais: %s" % ("Sim" if psk_a == psk_b else "Não"))
    print(psk_a)
    print(psk_b)
