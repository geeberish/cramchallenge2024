import math

# modified
base = 5.9

# 0 you suck, 0.5 is avg, (0.7 mod = base), 1 perfect
physical = 0.4

# 0 you suck, 0.5 is avg, (0.7 mod = base), 1 perfect
personnel = 0.6

# 0 you suck, 0.5 is avg, (0.7 mod = base), 1 perfect
# if its bad it hurts, if its 0.7 or better its awesome and helps
policies = 0.5

#heavy weight
criticality = 2

#heavy weight
apt = 0.4


overall = 0

#print("Overall: ", overall, "Base: ", base, "Physical: ", physical, "Personnel: ", personnel, "Policies: ", policies, "Criticality: ", criticality, "Apt: ", apt)

def calculation():
    return overall