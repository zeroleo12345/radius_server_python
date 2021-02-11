## Dictionary source
1. pyrad library
2. freeradius


## Modify Point
- remove encrypt=2 in dictionary.microsoft
```
ATTRIBUTE      MS-MPPE-Send-Key                        16      octets  encrypt=2
ATTRIBUTE      MS-MPPE-Recv-Key                        17      octets  encrypt=2
```
