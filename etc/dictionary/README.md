## Dictionary source
- pyrad library (https://github.com/pyradius/pyrad/blob/master/example/dictionary)
- freeradius (./third_party/freeradius-3.2.3/share)


## Modify Point
- remove encrypt=2 in dictionary.microsoft
```
ATTRIBUTE      MS-MPPE-Send-Key                        16      octets  encrypt=2
ATTRIBUTE      MS-MPPE-Recv-Key                        17      octets  encrypt=2
```

- change type to octets from string in dictionary.pyrad
```
ATTRIBUTE	User-Password		2	string
ATTRIBUTE  CHAP-Challenge      60  string
ATTRIBUTE	EAP-Message		79	string
```
