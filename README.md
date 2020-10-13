eCoupon MultiToken SmartContract
====================================

Build/Basic Usage
-----------------

### Dependencies

This project depends only on SmartPy, you can install SmartPy by doing a:

```
$ curl -s https://SmartPy.io/dev/cli/SmartPy.sh -o /tmp/SmartPy.sh
$ chmod +x /tmp/SmartPy.sh
$ /tmp/SmartPy.sh local-install-auto smartpy
```

### Build

```
$ ./smartpy/SmartPy.sh compile ecoupon_multi_token.py "ECouponMultiToken(sp.address('tz1ZnCWM9yVcC3Dnbrk6HCCLjzeZpDUJrXbm'))" out
```

### Test
```
$ ./smartpy/SmartPy.sh test ecoupon_multi_token.py out
```