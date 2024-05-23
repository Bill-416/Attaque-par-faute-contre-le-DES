from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


chiffre_faux = ["D2FA53AC4FB9A7C2",
                "92E2C1B50FA8E7C2",
                "B2E251A50BA8A6C3",
                "12EA40B54FBCE3E2", 
                "93EB45A51FA827C4", 
                "93EA04A54FBE87C2",
                "D3EA55A407BAA7C3", 
                "92EA41856BBCA7C2", 
                "93FAC5F74FBDE7C2",
                "92E861E54BBDA682", 
                "9AE845E41FB9A7C2",
                "F2EA51A54BFCA78A",
                "92FB00A54FBD8752",
                "92EF51A54F7CAFC2",
                "93FF41E15D3DA7C2",
                "D2EA41AC07ECA7C2",
                "92EB61354ABCE292",
                "926A49B40EBCA3C2",
                "906E41B14EBDA3C6",
                "9AAA41A41FACA7C0",
                "86EA10A54EFCABE2",
                "96AA44A55F9CA5C2",
                "96EA40A5CE9CE3D6",
                "93AA45A35DBCA7C2",
                "86EA08840BBCB782",
                "92DA43A54BBDB7C2",
                "06CA40B54ABCB7C2",
                "90FA41E54FBCA756",
                "D2AA45A55FBCA48B",
                "92EB51A54FB427C7",
                "82EA10A56FB4B683",
                "92EE4125CFBCA3D2"]


def hexa_a_bin(chaine_hexa):
    decimal = int(chaine_hexa, 16)
    chaine_bin = bin(decimal)[2:]
    chaine_bin = chaine_bin.zfill(64)
    return chaine_bin


def permutation_initiale(bits):
    # Tableau IP (Initial Permutation)
    table_IP = [
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    ]

    # Vérification si la longueur de bits est égale à 64
    if len(bits) != 64:
        raise ValueError("La chaîne de caractères doit contenir exactement 64 bits.")

    # Initialisation de la chaîne de résultat
    resultat = ''

    # Application de la permutation initiale
    for index in table_IP:
        resultat += bits[index - 1]

    return resultat


def xor_strings(string1, string2):
    # Initialiser la chaîne résultante
    result = ""

    # Déterminer la longueur minimale entre les deux chaînes
    min_length = min(len(string1), len(string2))

    # Effectuer l'opération XOR bit à bit pour la longueur minimale
    for bit1, bit2 in zip(string1[:min_length], string2[:min_length]):
        # Convertir les bits en entiers et effectuer l'opération XOR
        result += str(int(bit1) ^ int(bit2))

    # Ajouter les bits restants de la chaîne la plus longue
    if len(string1) > len(string2):
        result += string1[min_length:]
    elif len(string2) > len(string1):
        result += string2[min_length:]

    return result


def expansion(bits):
    # Vérification si la longueur de bits est égale à 32
    if len(bits) != 32:
        raise ValueError("La chaîne de caractères doit contenir exactement 32 bits.")

    # Table d'expansion E
    expansion_table = [
        32, 1,  2,  3,  4,  5,
        4,  5,  6,  7,  8,  9,
        8,  9,  10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    ]

    # Appliquer la table d'expansion E
    result = ""
    for index in expansion_table:
        result += bits[index - 1]

    return result


def permutation(bits):
    # Vérification si la longueur de bits est égale à 32
    if len(bits) != 32:
        raise ValueError("La chaîne de caractères doit contenir exactement 32 bits.")

    # Table de permutation P
    permutation_table = [
        16, 7,  20, 21,
        29, 12, 28, 17,
        1,  15, 23, 26,
        5,  18, 31, 10,
        2,  8,  24, 14,
        32, 27, 3,  9,
        19, 13, 30, 6,
        22, 11, 4,  25
    ]

    # Appliquer la permutation P
    result = ""
    for index in permutation_table:
        result += bits[index - 1]

    return result


def s_box(input_bits, s_box_number):
    # Vérification si la longueur de bits est égale à 6
    if len(input_bits) != 6:
        raise ValueError("La chaîne de caractères doit contenir exactement 6 bits.")

    # Définition des S-boxes du DES
    s_boxes = [
        # S-box 1
        [
            [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
        ],
        # S-box 2
        [
            [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
        ],
        # S-box 3
        [
            [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
        ],
        # S-box 4
        [
            [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
        ],
        # S-box 5
        [
            [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
        ],
        # S-box 6
        [
            [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
        ],
        # S-box 7
        [
            [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
        ],
        # S-box 8
        [
            [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
        ]
    ]

    # Convertir les bits d'entrée en indice de ligne et de colonne pour accéder à la valeur de substitution
    row = int(input_bits[0] + input_bits[5], 2)
    column = int(input_bits[1:5], 2)

    # Obtenir la valeur de substitution de la S-box
    substitution_value = s_boxes[s_box_number][row][column]

    # Convertir la valeur de substitution en binaire sur 4 bits
    output_bits = format(substitution_value, '04b')

    return output_bits


def inverse_permutation(bits):
    if len(bits) != 32:
        raise ValueError("La chaîne de caractères doit contenir exactement 32 bits.")
    
    # Table inverse de P
    inverse_p_table = [
        9, 17, 23, 31, 13, 28, 2, 18,
        24, 16, 30, 6, 26, 20, 10, 1,
        8, 14, 25, 3, 4, 29, 11, 19,
        32, 12, 22, 7, 5, 27, 15, 21
    ]
    
    result = ""
    for index in inverse_p_table:
        result += bits[index - 1]

    return result


def increment_bits(bits):
    # Vérifier si la chaîne contient uniquement des caractères '0' et '1'
    if not all(c in '01' for c in bits):
        raise ValueError("La chaîne de caractères doit contenir uniquement des bits (0 ou 1).")
    
    # Convertir la chaîne de bits en un entier
    num = int(bits, 2)
    
    # Incrémenter le nombre binaire
    num += 1
    
    # Calculer la longueur originale de la chaîne de bits
    original_length = len(bits)
    
    # Convertir le nombre incrémenté en chaîne binaire de la même longueur
    result = format(num, f'0{original_length}b')
    
    return result


def binary_to_hex(binary_str):
    decimal = int(binary_str, 2)
    hex_str = hex(decimal)[2:]  # Remove '0x' prefix
    return hex_str.upper()  


def attaque(chiffree_faux_hexa):
    chiffree_juste_hexa = "92 EA 41 A5 4F BC A7 C2"
                          
    chiffree_juste_hexa = chiffree_juste_hexa.replace(" ", "")
    chiffree_faux_hexa  = chiffree_faux_hexa.replace(" ", "")

    chiffree_juste_bin = hexa_a_bin(chiffree_juste_hexa)
    chiffree_faux_bin  = hexa_a_bin(chiffree_faux_hexa)
    resultat_juste = permutation_initiale(chiffree_juste_bin)
    resultat_faux  = permutation_initiale(chiffree_faux_bin)

    r_16 = resultat_juste[0:32]
    r_15= l_16 = resultat_juste[32:]

    r_16_avec_faute = resultat_faux[0:32]
    r_15_avec_faute = l_16_avec_faute = resultat_faux[32:]

    faute = xor_strings(l_16, l_16_avec_faute)
    
    #####################################################
    k_16_6bits = "0" * 6
    k_16 = [[] for _ in range(8)]

    #tmp = inverse_permutation(xor_strings(l_16, l_16_avec_faute))
    tmp = inverse_permutation(xor_strings(r_16, r_16_avec_faute))
    liste = [tmp[i*4:i*4+4] for i in range(8)]
    
    r_15 = expansion(r_15)
    r_15_avec_faute = expansion(r_15_avec_faute)
    
    r_15_6 = [r_15[i*6:i*6+6] for i in range(8)]
    r_15_avec_faute_6 = [r_15_avec_faute[i*6:i*6+6] for i in range(8)]
    
    
    while k_16_6bits != "1000000":

        resultat = []
    
        for i in range(8):
            tmp1 = s_box(xor_strings(r_15_6[i], k_16_6bits), i)
            tmp2 = s_box(xor_strings(r_15_avec_faute_6[i], k_16_6bits), i)
            resultat.append(xor_strings(tmp1, tmp2))

            if liste[i] == resultat[i] and liste[i] != "0000":
                k_16[i].append(k_16_6bits)
              
        
        k_16_6bits = increment_bits(k_16_6bits)
    
    return k_16


def inverse_pc2(bits):
    if len(bits) != 48:
        raise ValueError("La chaîne de caractères doit contenir exactement 48 bits.")
    inverse_pc2_table = [5 , 24, 7 , 16, 6 , 10 , 20, 
                         18, ' ', 12, 3 , 15, 23, 1 , 
                         9 , 19, 2 , ' ', 14, 22, 11, 
                         ' ', 13, 4 , ' ', 17, 21, 8 , 
                         47, 31, 27, 48, 35, 41, ' ', 
                         46, 28, ' ', 39, 32, 25, 44, 
                         ' ', 37, 34, 43, 29, 36, 38, 
                         45, 33, 26, 42, ' ', 30, 40]

    resultat = ""
    for index in inverse_pc2_table:
        if index != ' ':
            resultat += bits[index - 1]
        else:
            resultat += ' '
            
    return resultat


def inverse_pc1(bits):
    if len(bits) != 56:
        raise ValueError("La chaîne de caractères doit contenir exactement 56 bits.")
    
    inverse_pc1 = [8, 16, 24, 56, 52, 44, 36, ' ', 
                   7, 15, 23, 55, 51, 43, 35, ' ', 
                   6, 14, 22, 54, 50, 42, 34, ' ', 
                   5, 13, 21, 53, 49, 41, 33, ' ',
                   4, 12, 20, 28, 48, 40, 32, ' ', 
                   3, 11, 19, 27, 47, 39, 31, ' ', 
                   2, 10, 18, 26, 46, 38, 30, ' ', 
                   1,  9, 17, 25, 45, 37, 29, ' ']
    
    
    resultat = ""
    for i in range(64):
        if inverse_pc1[i] != ' ':
            resultat += bits[inverse_pc1[i] - 1]
        else:
            resultat += ' '
            
    return resultat


def bits_to_bytes(bits):
    # Vérifier que la chaîne de bits contient uniquement '0' et '1'
    if not all(c in '01' for c in bits):
        raise ValueError("La chaîne de caractères doit contenir uniquement des bits (0 ou 1).")

    # Ajouter des zéros initiaux pour que la longueur des bits soit un multiple de 8
    bits = bits.zfill((len(bits) + 7) // 8 * 8)

    # Convertir la chaîne de bits en un entier
    num = int(bits, 2)

    # Convertir l'entier en une séquence de bytes
    byte_array = num.to_bytes((len(bits) + 7) // 8, byteorder='big')

    # Convertir la séquence de bytes en une chaîne de caractères représentant les octets en décimal
    byte_string = ' '.join(str(byte) for byte in byte_array)

    return byte_string

def chiffrement_DES(key, clair):
    
    cipher = DES.new(key, DES.MODE_ECB)
    # Chiffrer les données
    encrypted_data = cipher.encrypt(clair)

    return encrypted_data
    

dic = {}
tmp = "chiffré"

for i in range(32):
    dic[tmp+str(i)] = attaque(chiffre_faux[i])

k_16 = ""
for i in range(8):
    sets = []
    for k in dic.keys():
        if len(dic[k][i]) != 0:
            sets.append(set(dic[k][i]))
     
    common_elements = set.intersection(*sets)
    common_elements_str = ''.join(map(str, common_elements))
    k_16 += common_elements_str

print("La clé K16: {}".format(binary_to_hex(k_16)))
    
tmp = inverse_pc2(k_16)
cle_48bits = inverse_pc1(tmp)
cle_48bits = cle_48bits.replace(' ', '*')

print("Les 48 bits de la clé: {}".format(cle_48bits))

cle_48bits = list(cle_48bits)

_8bits = '0'* 8
chiffre = "92EA41A54FBCA7C2"
clair   = "85F26EAB1F0BEF49"
clair = hexa_a_bin(clair)

"""
_chiffre = ""
while _chiffre != chiffre:
    indice = 0
    nb_des_1 = 0
    key = ""
    for i in range(1, 65):
        if cle_48bits[i-1] == '*' and i % 8 != 0:
            cle_48bits[i-1] = _8bits[indice]
            indice += 1
    _8bits = increment_bits(_8bits)
    
    for i in range(1, 65):
        if cle_48bits[i-1] == '1':
            nb_des_1 += 1
        if  i % 8 == 0:
            if nb_des_1 % 2 == 0:
                cle_48bits[i-1] = '1'
            else:
                cle_48bits[i-1] = '0'
            nb_des_1 = 0
    
        key += cle_48bits[i-1]
    
    key = int(key, 2).to_bytes(len(key) // 8, byteorder='big')

    _chiffre = chiffrement_DES(key, clair)
    _chiffre = binary_to_hex(_chiffre)
"""