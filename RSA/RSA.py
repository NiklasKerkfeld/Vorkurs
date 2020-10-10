import random
import math


def is_prim(number):
    """
    testet ob prim
    :param number: number
    :return: bool
    """
    for x in range(2, int(math.sqrt(number)+1)):
        if number % x == 0:
            return False
    return True


def generate_prim(scale):
    """
    generiert eine Primzahl durch zufälliges durchtesten
    :param scale: Primzahl zwischen 10^scale und 10^(scale+1)
    :return: Primzahl
    """
    numbers = [i for i in range(10 ** scale, 10 ** (scale + 1))]
    random.shuffle(numbers)
    for num in numbers:
        if is_prim(num):
            return num


def teiler(x):
    """
    gibt Liste mit möglichen teiler einer Zahl
    :param x:
    :return:
    """
    numbers = range(2, int(x // 2) + 1)
    t = []
    for num in numbers:
        if x % num == 0:
            t.append(num)
    return t


def teilerfremd(num1, num2):
    """
    gibt an ob zwei Zahlen teilerfremd sind
    :param num1: Zahl 1
    :param num2: Zahl 2
    :return: bool
    """
    t1, t2 = teiler(num1), teiler(num2)
    both = [i for i in t1 if i in t2]
    if len(both) == 0:
        return True
    else:
        return False


def generate_teilerfremd(x):
    numbers = [i for i in range(2, x)]
    random.shuffle(numbers)
    for num in numbers:
        if teilerfremd(x, num):
            return num


def erwEuklAlg(num1, num2):
    """
    erweiterter Euklidischer Algorithmus
    :param num1: Zahl 1
    :param num2: Zahl 2
    :return: ggt, tabelle
    """
    b = min(num1, num2)
    a = max(num1, num2)
    q = a // b
    tab = [[a, b, q]]
    while b > 0:
        new_a = b
        new_b = a % b               # a mod b
        if new_b != 0:
            q = new_a // new_b      # Ganzzahldivision
        else:
            q = None

        tab.append([new_a, new_b, q])
        a, b = new_a, new_b

    ggt = a

    # berechnung von s und t
    # ggt = s * a + t * b
    s, t = 1, 0                 # da ggt = a in der letzten Zeile
    tab[-1].extend([s, t])      # erweitern der tabelle um s und t

    for idx in range(len(tab)-2, -1, -1):

        q = tab[idx][2]
        s = tab[idx+1][4]
        t = tab[idx+1][3] - q * tab[idx+1][4]
        tab[idx].extend([s,t])

    return ggt, tab


def encoding(number, e, N):
    return (number ** e) % N


def decrypt(message, d, N):
    return (message ** d) % N


def demo(text=230, p=0, q=0):
    """
    Führt eine RSA-Verschlüsselung druch und printed alle Zwischenergebnisse
    :param text: zu verschlüsselnde Nachricht
    :param p: 1. Primzahl (default: 0 => generierte Primzahl
    :param q: 2. Primzahl (default: 0 => generierte Primzahl
    """

    # generiere zwei ungleiche Primzahlen
    while p == q:
        p, q = generate_prim(2), generate_prim(2)
    print(f'Primzahlen: {p}, {q}')

    # berechne N
    N = p * q
    print(f'N: {N}')

    # berechne die eulersche Funktion (Phi(N) = (p - 1) * (q -1)
    phiN = (p - 1) * (q - 1)
    print(f'eulersche Funktion: {phiN}')

    # wähle eine teilerfremde Zahl zur eulerschen Funktion
    e = generate_teilerfremd(phiN)
    print(f'teilerfremde Zahl zu eulerschen Funktion: {e}')

    print(f'öffentlicher Schlüssel e={e} und N={N}')
    # bereche den Enschlüsselungsexponenenten d
    # es gilt: e * d = 1 mit (mod eulfunk)
    ggt, tab = erwEuklAlg(e, phiN)
    d = tab[0][-1]

    # wenn d negativ ist gilt d = d mod phi(N)
    if d < 0:
        d = d % phiN

    # jetzt müssen die Bedigungen erfült sein
    # d * e + s * phi(N) = ggt
    print(f'd * e + s * phi(N) = ggt: {tab[0][-1] * e + tab[0][-2] * phiN == ggt}')
    # (e * d) mod phi(N) = 1
    print(f'(e * d) mod phi(N) = 1: {(e * d) % phiN == 1}')

    print(f'Entschlüsselungsexponent: {d}')

    print()
    print(f'tabelle zum erweiterten Euklidischen Algorithmus:')
    for item in tab:
        print(item)

    print('\n')

    print(f'zu verschlüsselnde Nachricht: {text}')
    message = encoding(text, e, N)
    print(f'message: {message}')
    print(f'text: {decrypt(message, d, N)}')
    print('\n')

def generate_encoding(p=0, q=0):
    """
    generiert einen öffentlichen und einen privaten Key zum verschlüsseln von Nachrichten
    :param p: 1. Primzahl (default: 0 => generierte Primzahl
    :param q: 2. Primzahl (default: 0 => generierte Primzahl
    :return: öffentlicher Schlüssel (e), privater Schlüssel (d) und N
    """

    # generiere zwei ungleiche Primzahlen
    while p == q:
        p, q = generate_prim(2), generate_prim(2)

    # berechne N
    N = p * q

    # berechne die eulersche Funktion (Phi(N) = (p - 1) * (q -1)
    phiN = (p - 1) * (q - 1)

    # wähle eine teilerfremde Zahl zur eulerschen Funktion
    e = generate_teilerfremd(phiN)

    # bereche den Enschlüsselungsexponenenten d
    # es gilt: e * d = 1 mit (mod eulfunk)
    ggt, tab = erwEuklAlg(e, phiN)
    d = tab[0][-1] # % eulfunk
    if d < 0:
        d = d % phiN

    return e, d, N


if __name__ == '__main__':
    # verschlüsselt und Entschlüsselt einen Text und printed alle Zwischenergebnisse
    demo(230)

    e, d, N = generate_encoding()
    text = 555
    message = encoding(text, e, N)
    print(message)
    text_back = decrypt(message, d, N)
    print(text_back)
