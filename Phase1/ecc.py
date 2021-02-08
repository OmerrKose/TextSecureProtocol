from random import randint, seed
from sympy import isprime 

def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
    gcd = b
    return gcd, x, y

def modinv(a, m):
    gcd, x, y = egcd(a, m)
    if gcd != 1:
        return None  # modular inverse does not exist
    else:
        return x % m

class point:
    def __init__(self, x, y):
        self.x = x
        self.y = y
    def add(self, Q, curve):
        xp = self.x
        yp = self.y
        xq = Q.x
        yq = Q.y
        a = curve.a
        b = curve.b
        p = curve.p
        if(self.x == 0 and self.y == 0):   # if self is point at infinity, return Q
            return Q
        elif(Q.x == 0 and Q.y == 0):       # if Q is point at infinity, return self 
            return self
        elif(self.x == Q.x and self.y == (-Q.y)%p):   # if self = -Q return point at infinity
            return point(0,0)
        elif(self.x == Q.x and self.y == Q.y):        # if self = P lambda is computed differently
            lam = ((3*xp**2+a)*modinv(2*yp%p, p))%p
        else:    
            lam = ((yq-yp)*modinv((xq-xp)%p, p))%p    # if self !=P lambda is computed differently
        xr = (lam**2-(xp+xq))%p
        yr = (lam*(xp-xr)-yp)%p
        return point(xr,yr)
    def mult(self, k, curve):           # binary left to right algorithm 
        Q = point(0,0)     
        T = point(self.x, self.y)
        kk = k
        while (kk!=0):
            if (kk%2 == 1):
                Q = Q.add(T,curve)      # point addition instead of modular multiplication
            kk = kk>>1
            if(kk!=0):
                T = T.add(T, curve)     # point doubling instead of modular squaring
        return point(Q.x,Q.y)

class curve:
    def __init__(self, a, b, p):
        self.a = a
        self.b = b
        self.p = p
        self.points = []
        self.n = 0   # order of the curve (i.e., number of points)
        disc = -16*(4*self.a**3+27*self.b**2)%p
        if disc == 0:
            print("Warning: singular curve")
    def find_points(self):
        qr = []
        sqroots = []
        for x in range(1,self.p):
            x2 = x*x%self.p
            if (x2 not in qr):
                qr.append(x2)
                sqroots.append(x)
        for x in range(0,p):
            y2 = (x**3 + self.a*x + self.b)%self.p
            if (y2 == 0):
                self.points.append(point(x,0))
                self.n = self.n+1
            if y2 in qr:
                y = qr.index(y2)+1
                self.n = self.n+1
                self.points.append(point(x,y))
                if (y!=0):
                    self.points.append(point(x,self.p-y))
                    self.n = self.n+1
                #print qr.index(y2)+1
        self.points.append(point(0,0))
        self.n = self.n+1
    def random_point(self):
        i = randint(0, self.n-1)
        return self.points[i]
    def all_points(self):
        return self.points
        

seed(20)   # if you want the same parameters, uncomment this
p = 177
a = 1
b = 5

while True:
    p = randint(3,32)
    if isprime(p):
        break
while True:
    a = randint(0, p-1)
    b = randint(1, p-1)  # problem with point at infinity if b = 0
    disc = (-16*(4*a**3+27*b**2))%p
    if disc != 0:
        print("disc: ", disc)
        break

EC = curve(a, b, p)
print("a, b, p: ", EC.a, EC.b, EC.p)

EC.find_points()
n = EC.n
print("Order of the curve (n): ", n)
print("All points: ")
points = EC.all_points()
for i in range(0,n): print (points[i].x, points[i].y)

# Find two random points
print("\nPerform EC arithmetic")
P = EC.random_point()
Q = EC.random_point()
print("A random point P: ", P.x, P.y)
print("Another random point Q: ", Q.x, Q.y)
R = P.add(Q, EC)  # add them
# Check if R is on the curve
if (R.y*R.y)%p == (R.x**3 + EC.a*R.x+EC.b)%p:
    print("The point R = P+Q is on the curve")

for k in range(1, n+2):
    S = P.mult(k, EC)
    if S.x == 0 and S.y == 0:
        continue
    if (S.y*S.y)%p != (S.x**3 + EC.a*S.x+EC.b)%p:
        print("The point S is NOT on the curve")
        print(S.x, S.y)




