# Easy PBKDF2 for node.js

Easy PBKDF2 makes it easier to create secure, individually salted, password hashes using PBKDF2.

This implementation is based on StackExchange's own Open Sourced PBKDF2 methods.

## Installation:

via cmd line:

```bash
$ npm install easy-pbkdf2
```

or in your `package.json`:

```json
"dependencies": {
    "easy-pbkdf2": "0.0.2"
}
```

## Usage:
```js
var easyPbkdf2 = require("easy-pbkdf2")();
var salt = easyPbkdf2.generateSalt();
var password = "RandomDigits";
easyPbkdf2.secureHash( password, salt, function( err, passwordHash, originalSalt ) {
    // use your own db's methods to save the hashed password AND salt.
    currentUser.update({
        // The Base64 encoded hash, 344 characters long
        "password_hash": passwordHash,
        // Salt length varies based on SALT_SIZE. The default SALT_SIZE of
        // 32 produces a value that is:
        // (SALT_SIZE.toString(16).length) + 1 + base64EncodedSalt.length)
        // characters long (42 characters).
        "salt": originalSalt // === salt
    });
});

// ...

// sometime later:
function authenticate( user, userEnteredPassword, callback ){
    easyPbkdf2.secureHash( userEnteredPassword, user.salt, function( err, passwordHash, salt ) {
        // make sure the user-entered password is equal to the previously
        // created hash when hashed with the same salt.
        callback( passwordHash === user.password_hash );
    });
}
```

You can also have easyPbkdf2 generate the salt for you by omitting the `salt` parameter:

```js
easyPbkdf2.secureHash( password, function( err, passwordHash, newSalt ) {
    // save newSalt somewhere!
});
```

To create a new instance of `EasyPbkdf2`: 

```js
    var easyPbkdf2 = require("easy-pbkdf2")();
```

You can also use the following methods of instantiation:

```js
// the EasyPbkdf2 constructor
var EasyPbkdf2 = require("easy-pbkdf2"),
    easyPbkdf2;

easyPbkdf2 = EasyPbkdf2(options);
easyPbkdf2 = new EasyPbkdf2(options);
easyPbkdf2 = EasyPbkdf2.EasyPbkdf2(options);
easyPbkdf2 = new EasyPbkdf2.EasyPbkdf2(options);
```

of which all will return an `EasyPbkdf2` instance with `options` set.

## Options

```js
 var options = {
    // default DEFAULT_HASH_ITERATIONS is 512
    "DEFAULT_HASH_ITERATIONS": 256,
    // default SALT_SIZE is 32
    "SALT_SIZE": 16,
    // default KEY_SIZE is 256
    "KEY_SIZE": 128
};

var easyPbkdf2 = new EasyPbkdf2(options);
console.log(easyPbkdf2.DEFAULT_HASH_ITERATIONS) // 256
console.log(easyPbkdf2.SALT_SIZE); // 16
console.log(easyPbkdf2.KEY_SIZE); // 128

// options are applied to each instance individually.
console.log( (new EasyPbkdf2()).DEFAULT_HASH_ITERATIONS ); // 512
```

## Methods

###`weakHash( value )`

> Cranks out a collision resistant hash, relatively quickly.  
> Not suitable for passwords, or sensitive information.  
*Synchronous only*  

#### Params:
 - **value**: String or Object. Base64 encoded sha1 hash of `value`

#### Returns:
 - A string; Base64 encoded sha1 hash of `value`

---

###`random( bytes, callback )`

> Universal random provider. Generates cryptographically strong pseudo-random data.  
*Syncronous or Asyncronous*

#### Params:
  - **bytes**: Number. The number of bytes to return.
  - **callback**: Function. The callback to call for async operation (optional)

#### Returns:
 - A SlowBuffer; A buffer containing therandom bytes. (optional)

---

###`generateSalt( explicitIterations, callback )`

> Convenience wrapper around .random to grab a new salt value.  
> Treat this value as opaque, as it captures iterations.  
*Synchronous or Asynchronous*

#### Params:
 - **explicitIterations**: Number. An integer (optional)
 - **callback**: Function. (optional)

#### Returns:
 - A String. Return iterations and salt together as one string ({hex-iterations}.{base64-salt}) (optional)

---

###`secureHash( value, salt, callback )`

> Alias for [`hash`](#hash-value-salt-callback-).

---

###`hash( value, salt, callback )`

> Backs Secure hashes.  
> Uses PBKDF2 internally, as implemented by the node's native crypto library.  
> See http://en.wikipedia.org/wiki/PBKDF2  
> and http://code.google.com/p/crypto-js/ for more information.  
*Asynchronous only*

#### Params:
 - **value**: String. The value/password you want to hash.
 - **salt**: String. salt (should include iterations). Automatically created if omitted. (optional)
 - **callback**: Function. fn( {Error} err, {String} A secure hash (base64 encoded), {String} the original or newly created salt ).

## Issues

Please file them here: [https://github.com/davidmurdoch/easy-pbkdf2/issues](https://github.com/davidmurdoch/easy-pbkdf2/issues).

And remember: pull requests are very welcome. :-)
