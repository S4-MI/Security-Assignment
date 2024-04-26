import random
import time


def is_prime(n):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

        for _ in range(100):
            a = random.randint(2, n - 1)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True


def generate_prime(bits):
    while True:
        prime_candidate = random.getrandbits(bits)
        if is_prime(prime_candidate):
            return prime_candidate


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1


def generate_keypair(k):
    start = time.time()
    p = generate_prime(k // 2)
    q = generate_prime(k // 2)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = random.randint(2, phi - 1)
    while gcd(e, phi) != 1:
        e = random.randint(2, phi - 1)

    d = mod_inverse(e, phi)
    end = time.time()
    return {
        'keys': ((e, n), (d, n)),
        'time': end - start
    }


def encrypt(public_key, plaintext):
    start = time.time()

    key, n = public_key
    cipher = [pow(ord(char), key, n) for char in plaintext]

    end = time.time()
    return {
        'cipher_text': cipher,
        'time': end - start,
    }


def decrypt(private_key, ciphertext):
    start = time.time()

    key, n = private_key
    plain = [chr(pow(char, key, n)) for char in ciphertext]

    plain_text = ''.join(plain)

    end = time.time()
    return {
        'plain_text': plain_text,
        'time': end - start,
    }


def main():
    k = int(input("Bit Size = "))
    key_result = generate_keypair(k)
    public_key, private_key = key_result['keys']
    print("\nPublic Key: (e, n) = ", public_key)
    print("Private key: (d, n) = :", private_key)

    plaintext = input("\nPlaintext: \n")
    encryption_result = encrypt(public_key, plaintext)
    ciphertext = encryption_result['cipher_text']
    print("Encrypted Text(ASCII):")
    print(ciphertext)

    decryption_result = decrypt(private_key, ciphertext)
    decrypted_plaintext = decryption_result['plain_text']
    print("\nDecrypted Text:")
    print(decrypted_plaintext)

    print('\n\nExecution Time:')
    print(f'Key Generation: {key_result["time"]}')
    print(f'Encryption Time: {encryption_result["time"]}')
    print(f'Decryption Time: {decryption_result["time"]}')


if __name__ == '__main__':
    main()
