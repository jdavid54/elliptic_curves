# Super simple Elliptic Curve Presentation. No imported libraries, wrappers, nothing. 
# For educational purposes only. Remember to use Python 2.7.6 or lower. You'll need to make changes for Python 3.
# Original source: https://github.com/wobine/blackboard101/blob/master/EllipticCurvesPart4-PrivateKeyToPublicKey.py
debug = False

# secp256k1 domain parameters
Pcurve = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 -1 # The proven prime
Acurve = 0; # These two defines the elliptic curve. y^2 = x^3 + Acurve * x + Bcurve
Bcurve = 7;
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
if debug : print(Gx)
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
if debug : print(Gy)
GPoint = (Gx, Gy) # This is our generator point.
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 # Number of points in the field

# Replace with any private key
privKey = 0x79FE45D61339181238E49424E905446A35497A8ADEA8B7D5241A1E7F2C95A04D
#Public Key (130 characters [0-9A-F]):
#042A574EA59CAE80B09D6BA415746E9B031ABFBE83F149B43B37BE035B871648720336C5EB647E891C98261C57C13098FA6AE68221363C68FF15841B86DAD60241
#Public Key (compressed, 66 characters [0-9A-F]):
#032A574EA59CAE80B09D6BA415746E9B031ABFBE83F149B43B37BE035B87164872

#privKey = 0xA0DC65FFCA799873CBEA0AC274015B9526505DAAAED385155425F7337704883E
# https://www.bitaddress.org/bitaddress.org-v3.3.0-SHA256-dec17c07685e1870960903d8f58090475b25af946fe95a734f88408cef4aa194.html
#Public Key (130 characters [0-9A-F]):
#040791DC70B75AA995213244AD3F4886D74D61CCD3EF658243FCAD14C9CCEE2B0AA762FBC6AC0921B8F17025BB8458B92794AE87A133894D70D7995FC0B6B5AB90
#Public Key (compressed, 66 characters [0-9A-F]):
#020791DC70B75AA995213244AD3F4886D74D61CCD3EF658243FCAD14C9CCEE2B0A
#privKey = 0xEC81FBB2598C321D565908B40C287176F057379F38697AB8854AFAF3DB2CAE8A
#privKey = 0x6DDB241F46B14218830945C69F98742D243D9EF9164A25EEAA6DF2419DE8062A

def modinv(a,n=Pcurve): #Extended Euclidean Algorithm/'division' in elliptic curves
    lm, hm = 1,0
    low, high = a%n, n
    while low > 1:
        ratio = high//low
        nm, new = hm-lm*ratio, high-low*ratio
        lm, low, hm, high = nm, new, lm, low
    return lm % n

def ECadd(a,b): # EC Addition
    LamAdd = ((b[1]-a[1]) * modinv(b[0]-a[0],Pcurve)) % Pcurve
    x = (LamAdd*LamAdd-a[0]-b[0]) % Pcurve
    y = (LamAdd*(a[0]-x)-a[1]) % Pcurve
    return (x,y)

def ECdouble(a): # EC Doubling
    Lam = ((3*a[0]*a[0]+Acurve) * modinv((2*a[1]),Pcurve)) % Pcurve
    x = (Lam*Lam-2*a[0]) % Pcurve
    y = (Lam*(a[0]-x)-a[1]) % Pcurve
    return (x,y)

def EccMultiply(GenPoint,ScalarHex): # Doubling & Addition
    if debug :
        print('GenPoint=',GenPoint)
        print('PrivKey=',ScalarHex)
    if ScalarHex == 0 or ScalarHex >= N: raise Exception("Invalid Scalar/Private Key")
    # privKey in binary
    ScalarBin = str(bin(ScalarHex))[2:]
    if debug : print('0b'+ScalarBin)
    Q = GenPoint
    for i in range (1, len(ScalarBin)):
        # print(i,ScalarBin[i])
        # doubling Q
        Q=ECdouble(Q);
        if debug : print('DUB ', Q[0])
        if ScalarBin[i] == "1":
            # add Q to GenPoint
            Q=ECadd(Q,GenPoint);
            if debug : print('ADD ', Q[0])
        #print(i, Q)
    return (Q)

print()
print ("******* Bitcoin Public Key Generation *********")
print()
PublicKey = EccMultiply(GPoint,privKey)
print ("Private key (Hex):")
print (hex(privKey))
print()

print ("Public key x-value (Hex): ")
print ("0x" + "%064x" % int(PublicKey[0]))
#print()

print ("Public key y-value (Hex): ")
print ("0x" + "%064x" % int(PublicKey[1]))
print()

print ("Public key compressed : ")
print ("02" + "%064x" % int(PublicKey[0]))
print()


print ("Public key uncompressed : ")
print ("03" + "%064x" % int(PublicKey[0]) + "%064x" % int(PublicKey[1]))
print()


