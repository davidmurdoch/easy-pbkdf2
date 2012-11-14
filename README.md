# Easy PBKDF2 for node.js

Easy PBKDF2 makes it easier to create secure, individually salted, password hashes using PBKDF2.

This implementation is based on StackExchange's own Open Sourced PBKDF2 methods.

# To use:

```javascript
    var easyPbkdf2 = require("easy-pbkdf2")();
    var salt = easyPbkdf2.generateSalt();
    var password = "RandomDigits";
    easyPbkdf2.secureHash( password, salt, function( passwordHash ) {
        // use your own db's methods to save the hashed password AND salt.
        currentUser.update({
            // The Base64 encoded hash, 344 characters long
            "password_hash": passwordHash,
            // Salt length varies based on SALT_SIZE. The default SALT_SIZE of
            // 32 produces a value that is:
            // (SALT_SIZE.toString(16).length) + 1 + base64EncodedSalt.length)
            // characters long (42 characters).
            "salt": salt
        });
    });

    // ...

    // sometime later:
    function authenticate( user, userEnteredPassword, callback ){
        easyPbkdf2.secureHash( userEnteredPassword, user.salt, function( passwordHash ) {
            // make sure the user-entered password is equal to the previously
            // created hash when hashed with the same salt.
            callback( passwordHash === user.password_hash );
        });
    }
```

# Options

```
 var options = {
    // default DEFAULT_HASH_ITERATIONS is 512
    "DEFAULT_HASH_ITERATIONS": 256,
    // default SALT_SIZE is 32
    "SALT_SIZE": 16
};
```

# Methods

```
weakHash( value );
```
Cranks out a collision resistant hash, relatively quickly.
Not suitable for passwords, or sensitive information.
Synchronous

 ## Params:
 - **value**: String or Object. *Base64 encoded sha1 hash of `value*

 ## Returns:
 - A string; Base64 encoded sha1 hash of `value`


`secureHash` Alias for `hash`


```
random( bytes );
```

Universal random provider. Generates cryptographically strong pseudo-random data.
Synronous or Asyncronous

 ## Params:
  - **bytes** Number. The number of bytes to return.
  - **callback** Function. The callback to call for async operation (optional)

 ## Returns:
 - A SlowBuffer; A buffer containing therandom bytes. (optional)


```
generateSalt( explicitIterations, callback );
```

Convenience wrapper around .random to grab a new salt value.
 Treat this value as opaque, as it captures iterations.

 Synchronous or Asynchronous


 ## Params:
 - **value**: String or Object. *Base64 encoded sha1 hash of `value*
 - **explicitIterations** Number. An integer (optional)
 - **callback** Function. (optional)

 ## Returns:
 - A String. Return iterations and salt together as one string ({hex-iterations}.{base64-salt}) (optional)

```
secureHash()
```

Alias for `hash`


```
hash( value, salt, callback )
```


 Backs Secure hashes.

 Uses PBKDF2 internally, as implemented by the node's native crypto library.

 See http://en.wikipedia.org/wiki/PBKDF2
 and http://code.google.com/p/crypto-js/

 Asynchronous

 ## Params:
 - **value** String. MUST be a string, unless, of course, you want to explode.
 - **salt** String. salt (should include iterations.)
 - **callback** Function. fn( {String} A secure hash (base64 encoded) )


# Issues

Please file them here: [https://github.com/davidmurdoch/easy-pbkdf2/issues](https://github.com/davidmurdoch/easy-pbkdf2/issues).
Pull requests are very welcome.