## Dictionary source
1. pyrad library (https://github.com/pyradius/pyrad/blob/master/example/dictionary)
2. freeradius (./third_party/freeradius-3.2.3/share)


## Modify Point
- remove encrypt=2 in dictionary.microsoft
```
ATTRIBUTE      MS-MPPE-Send-Key                        16      octets  encrypt=2
ATTRIBUTE      MS-MPPE-Recv-Key                        17      octets  encrypt=2
```
