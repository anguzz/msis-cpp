
IP table notes: 
Address 198.116.48.0 /21.

* Network A: 255 hosts
* Network B: 3 hosts
* Network C: 73 hosts
* Network D: 148 hosts
* Network E: 514 hosts

| Network | Network Definition | Broadcast Address | Router Address | Total Hosts | Subnet Mask |
| ------- | ------------------ | ----------------- | -------------- | ----------- | ----------- |
| E       | 198.116.48.0       | 198.116.51.255    | 198.116.48.1   | 1022        | /22         | 
| A       | 198.116.52.0       | 198.116.53.255    | 198.116.52.1   | 510         | /23         |
| D       | 198.116.54.0       | 198.116.54.255    | 198.116.54.1   | 254         | /24         |
| C       | 198.116.55.0       | 198.116.55.127    | 198.116.55.1   | 126         | /25         |
| B       | 198.116.55.128     | 198.116.55.135    | 198.116.55.129 | 6           | /29         |


## Steps to Solve (example walkthrough)

1. **Start with given address space**
   network start = **198.116.48.0**

2. **Pick largest host requirement**

   - 514 hosts → need ≥ 514
   - /23 = 510 
   - /22 = 1022 
     choose **/22**

3. **Find which octet changes (from CIDR)**

   ```
   /1–8   → 1st
   /9–16  → 2nd
   /17–24 → 3rd
   /25–32 → 4th
   ```

   /22 → **3rd octet**

4. **Find block size (no mask needed)**
   remaining bits = 22 − 16 = 6
   block size = 256 ÷ 2^6 = **4**
   (3rd octet moves in steps of 4)

5. **Count ranges by block size**
   - 0–3, 4–7, 8–11, … **48–51**, 52–55
   - 48 falls inside **48–51**

6. **Assign addresses**

   * Network   = **198.116.48.0**
   * Broadcast = **198.116.51.255** (last in block)

7. **Router address**
   - network definition + 1 → **198.116.48.1**
   - it's the first address in the network definition

8. **Next network start**
   - broadcast + 1 →
   - 198.116.51.255 + 1 = **198.116.52.0**

9. **Repeat same steps for next rows**



### Mental shortcut version

* CIDR tells you the octet
* block size tells you the jump
* broadcast = last in jump
* next = +1

## CIDR Quick Reference Table

| CIDR | Subnet Mask     | Block Size*    | Total IPs | Usable Hosts |
| ---- | --------------- | -------------- | --------- | ------------ |
| /30  | 255.255.255.252 | 4              | 4         | 2            |
| /29  | 255.255.255.248 | 8              | 8         | 6            |
| /28  | 255.255.255.240 | 16             | 16        | 14           |
| /27  | 255.255.255.224 | 32             | 32        | 30           |
| /26  | 255.255.255.192 | 64             | 64        | 62           |
| /25  | 255.255.255.128 | 128            | 128       | 126          |
| /24  | 255.255.255.0   | 256            | 256       | 254          |
| /23  | 255.255.254.0   | 2 (3rd octet)  | 512       | 510          |
| /22  | 255.255.252.0   | 4 (3rd octet)  | 1024      | 1022         |
| /21  | 255.255.248.0   | 8 (3rd octet)  | 2048      | 2046         |
| /20  | 255.255.240.0   | 16 (3rd octet) | 4096      | 4094         |
| /19  | 255.255.224.0   | 32 (3rd octet) | 8192      | 8190         |


## CIDR calculation (no table)

**Finding CIDR from host count**

1. hosts + 2 (network + broadcast)
2. find next power of 2 → 2^n
3. host bits = n
4. CIDR = 32 − n
5. (optional) mask can be looked up if needed

### Subnet mask (reference only, usually not needed)

**How to get mask from CIDR (fast method)**

1. Every **8 bits = 255**
2. Find which octet CIDR falls into
3. Use the next value from this list for that octet:

```
0, 128, 192, 224, 240, 248, 252, 254, 255
```

---

### Steps

1. Fill full octets with **255**
2. Remaining bits → pick value from list above
3. Everything after → **0**



