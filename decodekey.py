from sympy import factorint

from Crypto.Util.number import inverse, long_to_bytes


N=26565161865307111818048461598499154074243202940204298826859108032012479209735882430347566051230277206771950228610144968894205047179268506019820727969529794

e=65537
cypher=10177208318108971112220599794161785526747855534021527962322166799130395251749131597687136565154077688176987603344304474820476849736333401005205589559549621

#find the prme factors of N
(p,q)=factorint(N)
print(p,", ",q)

phi=(p-1)*(q-1)
print(phi)


# from the encryption algorithm: (d*e)%phi=1

#the inverse modulo:
d=inverse(e,phi)

print(d)

# (cypher^d)%N  -> into bytes and then decoded
flag=long_to_bytes(pow(cypher,d,N)).decode()
print(flag)



