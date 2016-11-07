var crypto = require("crypto");

var EasyPbkdf2 = module.exports = function( options ) {
	if( !( this instanceof EasyPbkdf2 ) ){
		return new EasyPbkdf2( options );
	}

	if (options instanceof Object) {

		var keys = Object.keys(options);
		for(var i = 0; i<keys.length; i++)
			this[ keys[i] ] = options[ keys[i] ];
	}
};

EasyPbkdf2.prototype = {
	/**
	 * @constant The default number of iterations used by the hash method.
	 */
	"DEFAULT_HASH_ITERATIONS": 512,

	/**
	 * @default Salt sizes throughout the system
	 */
	"SALT_SIZE": 256/8,

	/**
	 * @default The length of the key to derive when hashing
	 */
	"KEY_LENGTH": 256,

	/**
	 * Cranks out a collision resistant hash, relatively quickly.
	 *
	 * Not suitable for passwords, or sensitive information.
	 *
	 * Synchronous
	 *
	 * @param {String|Object} value The data to hash. The value is converted to
	 * 	a string via JSON.stringify(). Do NOT pass a function.
	 * @returns {String} Base64 encoded sha1 hash of `value`
	 */
	"weakHash": function( value ) {
		var hasher = crypto.createHash("sha1"),
			bytes = value != null ? new Buffer( JSON.stringify( value ), "utf8" ) : new Buffer(0);

		hasher.update( bytes, "binary" );

		return hasher.digest("base64");
	},

	/**
	 * Cranks out a secure hash with a specific salt.
	 *
	 * Asynchronous
	 *
	 * @param {String} value
	 * @param {String} salt (optional)
	 * @param {Function} callback
	 */
	"secureHash": function(){
		return this.hash.apply( this, arguments );
	},

	/**
	 * Universal random provider. Generates cryptographically strong pseudo-random data.
	 *
	 * Synchronous or Asynchronous
	 *
	 * @param {Number} bytes
	 * @param {Function=} callback (optional)
	 * @returns {SlowBuffer} (optional)
	 */
	"random": function( bytes, callback ) {
		if ( callback instanceof Function ) {
			crypto.randomBytes( bytes, function( err, buffer ) {
				if ( err ) {
					console.log( err );
				}
				callback.call( this, buffer );
			});
		}
		else {
			try {
				var buffer = crypto.randomBytes( bytes );
				return buffer;
			}
			catch ( err ) {
				return null;
			}
		}
	},

	/**
	 * Convenience wrapper around .random to grab a new salt value.
	 * Treat this value as opaque, as it captures iterations.
	 *
	 * Synchronous or Asynchronous
	 *
	 * @param {Number=} explicitIterations An integer (optional)
	 * @param {Function=} callback (optional)
	 * @returns {String} Return iterations and salt together as one string ({hex-iterations}.{base64-salt}) (optional)
	 */
	"generateSalt": function( explicitIterations, callback ) {
		var defaultHashIterations = this.DEFAULT_HASH_ITERATIONS,
			saltSize = this.SALT_SIZE;

		if ( !callback && explicitIterations instanceof Function ) {
			callback = explicitIterations;
			explicitIterations = null;
		}

		if ( explicitIterations != null ) {
			// make sure explicitIterations is an integer
			var explicitIterationsInt = parseInt( explicitIterations, 10 );
			if ( explicitIterationsInt != explicitIterations || isNaN( explicitIterationsInt ) ) {
				throw new Error("explicitIterations must be an integer");
			}
			explicitIterations = explicitIterationsInt;
			// and that it is not smaller than our default hash iterations
			if ( explicitIterations < defaultHashIterations ) {
				throw new Error( "explicitIterations cannot be less than " + defaultHashIterations );
			}
		}

		// convert iterations to Hexadecimal
		var iterations = ( explicitIterations || defaultHashIterations ).toString( 16 );

		// get some random bytes
		if ( callback instanceof Function ) {
			this.random( saltSize, function( bytes ) {
				callback( concat( bytes ) );
			});
		}
		else {
			var bytes = this.random( saltSize );
			return concat( bytes );
		}

		function concat ( bytes ) {
			// concat the iterations and random bytes together.
			var base64 = binaryToBase64( bytes );
			return iterations + "." + base64;
		}
	},

	/**
	 * Backs Secure hashes.
	 *
	 * Uses PBKDF2 internally, as implemented by the node's native crypto library.
	 *
	 * See http://en.wikipedia.org/wiki/PBKDF2
	 * and http://code.google.com/p/crypto-js/
	 *
	 * If the salt param is omitted, generates salt automatically
	 *
	 * Asynchronous
	 *
	 * @param {String} value MUST be a string, unless, of course, you want to explode.
	 * @param {String} salt (should include iterations). (optional)
	 * @param {Function} callback fn( err, {String} A secure hash (base64 encoded), salt w/ iterations )
	 */
	"hash": function( value, salt, callback ) {
		// if salt was not supplied, generate it now.
		if ( salt instanceof Function || salt == null ) {
			callback = callback || salt;
			salt = this.generateSalt();
		}
		if ( !( callback instanceof Function ) ) {
			throw new Error("callback is required (as Function)");
		}
		if ( !value || typeof value !== "string" ) {
			callback(new Error("value is required (as String)"));
			return;
		}
		var keySize = this.KEY_LENGTH,
			i = (salt).indexOf("."),
			iterations = parseInt( salt.substring( 0, i ), 16 );

		crypto.pbkdf2( value, salt.substring( i + 1 ), iterations, keySize, "sha1", function( err, derivedKey ) {
			var base64;
			if ( !err ) {
				base64 = binaryToBase64( derivedKey );
			}
			callback( err, base64, salt );
		});
	},

	/**
	 * Verify that a plaintext value matches the given hash
	 * by hashing the value using the provided salt then comparing the two hashes
	 * using constant-time string comparison to prevent timing attacks.
	 *
	 * Asynchronous
	 *
	 * @param {String} salt The salt used to hash to `priorHash`.
	 * @param {String} priorHash The base64 encoded hash previously generated by the hash method.
	 * @param {String} value A plaintext string to compare against the `priorHash`.
	 * @param {Function} callback fn( err, {Boolean} True if the `value` matches the `priorHash`, false if not.
	 */
	"verify": function( salt, priorHash, value, callback ) {
		// calculate the original key length by checking the binary length of the base64 encoded priorHash
		var keyLength,
			easyPbkdf2;
		
		if ( !priorHash || !( typeof priorHash === "string" ) ) {
			callback( new Error("priorHash is required (as String)") );
			return;
		}
		keyLength = base64toBinary( priorHash ).length;
		easyPbkdf2 = new EasyPbkdf2({ "KEY_LENGTH": keyLength });
		easyPbkdf2.hash( value, salt, function( err, valueHash ) {
			var valid;
			if ( !err ) {
				valid = constantTimeStringCompare( priorHash, valueHash );
			}
			callback( err, valid );
		});
	}
};


EasyPbkdf2.EasyPbkdf2 = EasyPbkdf2;

/**
 * This method performs a constant-time (relevant to `constStr` only!) string equality check that can be used to prevent
 * timing attacks when comparing sensitive data.
 *
 * This method does not perform in constant-time when the variableStr is an empty string.
 *
 * @param {String} constStr The comparison string that this the constant-time function should be relative to.
 * @param {String} variableStr The string to check for equality
 * @returns {Boolean} True if the strings are equal. False if not.
 */
function constantTimeStringCompare( constStr, variableStr ) {
	with ( Object.create({}) ) { // disables compiler optimizations

		var aLength = constStr.length,
			bLength = variableStr.length,
			match = aLength === bLength ? 1 : 0,
			i = aLength;

		while ( i-- ) {
			var aChar = constStr.charCodeAt( i % aLength ),
				bChar = variableStr.charCodeAt( i % bLength ),
				equ = aChar === bChar,
				asInt = equ ? 1 : 0;
			match = match & equ;
		}

		return match === 1;
	}
}
function binaryToBase64( binary ){
	return new Buffer( binary, "binary" ).toString("base64");
}
function base64toBinary( base64 ){
	return new Buffer( base64, "base64" ).toString("binary");
}
