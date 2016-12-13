var crypto = require("crypto");

var EasyPbkdf2 = module.exports = function( options ) {
	if( !( this instanceof EasyPbkdf2 ) ){
		return new EasyPbkdf2( options );
	}

	if ( options ) {
		Object.keys( options ).forEach(function( key ){
			this[ key ] = options[key];
		}.bind( this ));
	}
};

EasyPbkdf2.prototype = {
	/**
	 * @constant The default number of iterations used by the hash method.
	 * 
	 * NIST recommends a minimum of 10000 iterations as of August 2016
	 */
	"DEFAULT_HASH_ITERATIONS": 32000,

	/**
	 * @default The hash algorithm to use
	 */
	"DIGEST": "sha256",

	/**
	 * @default Salt size, in bytes
	 */
	"SALT_SIZE": 32,

	/**
	 * @default The length of the key, in bytes, to derive when hashing
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
	 * @param {String} digest (optional) The digest to use when hashing the value.
	 * @returns {String} Base64 encoded hash of `value`
	 */
	"weakHash": function( value, digest ) {
		var hasher = crypto.createHash(digest || this.DIGEST),
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
		if ( isFunction( callback ) ) {
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
	 * @param {Number=} explicitIterations An integer used to override the instance's specified iterations. (optional)
	 * @param {Function=} callback (optional)
	 * @returns {String} Returns iterations, digest, and salt together as one string ({hex-iterations}.{digest}.{base64-salt}) (optional)
	 */
	"generateSalt": function( explicitIterations, callback ) {
		var defaultHashIterations = this.DEFAULT_HASH_ITERATIONS,
			saltSize = this.SALT_SIZE
			digest = this.DIGEST;

		if ( !callback && isFunction( explicitIterations ) ) {
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
		if ( isFunction( callback ) ) {
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
			return iterations + "." + digest + "." + base64;
		}
	},

	/**
	 * Parses salt into its three components: salt, iterations, and digest 
	 * @param {String} opaqueSalt Should include iterations and digst. Legacy salts without digest are supported. 
	 * @returns {String} Returns an object like: {salt: "salt", iterations: 1000, digest: "sha1"}
	 */
	"parseSalt": function( opaqueSalt ) {
		var iterationsEndIndex = opaqueSalt.indexOf("."),
			iterations = parseInt( opaqueSalt.substring( 0, iterationsEndIndex ), 16 ),
			digestEndIndex = opaqueSalt.indexOf(".", iterationsEndIndex + 1), 
			// Use the digest specified in the salt, if not present, fall back to sha1. Versions of easy-pbkdf2
			// before 2.0.0 did not include the digest in the salt.    
			digest = digestEndIndex === -1 ? "sha1" : opaqueSalt.substring( iterationsEndIndex + 1, digestEndIndex ),
			saltStringStart = digestEndIndex === -1 ? iterationsEndIndex : digestEndIndex;

		return {
			"salt": opaqueSalt.substring( saltStringStart + 1 ),
			"iterations": iterations,
			"digest": digest
		};
	},

	/**
	 * Backs Secure hashes.
	 *
	 * Uses PBKDF2 internally, as implemented by the node's native crypto library.
	 *
	 * See http://en.wikipedia.org/wiki/PBKDF2
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
		if ( isFunction( salt ) || salt == null ) {
			callback = callback || salt;
			salt = this.generateSalt();
		}
		if ( !isFunction( callback ) ) {
			throw new Error("callback is required (as Function)");
		}
		if ( !value || !isString(value) ) {
			callback(new Error("value is required (as String)"));
			return;
		}
		var parsedSalt = this.parseSalt(salt);

		crypto.pbkdf2( value, parsedSalt.salt, parsedSalt.iterations, this.KEY_LENGTH, parsedSalt.digest, function( err, derivedKey ) {
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
		
		if ( !priorHash || !isString( priorHash ) ) {
			callback( new Error("priorHash is required (as String)") );
			return;
		}
		keyLength = base64toBinary( priorHash ).length;
		var parsedSalt = this.parseSalt(salt);
		easyPbkdf2 = new EasyPbkdf2({ "KEY_LENGTH": keyLength, "DEFAULT_HASH_ITERATIONS": parsedSalt.iterations, "DIGEST": parsedSalt.digest });

		easyPbkdf2.hash( value, salt, function( err, valueHash ) {
			var valid;
			if ( !err ) {
				valid = constantTimeStringCompare( priorHash, valueHash );
			}
			callback( err, valid );
		});
	},

	/**
	 * Use this method to determine the optimal number of hash iterations needed to achieve the runtime of the given duration (in milliseconds).
	 * 
	 * // example:
	 * var easyPbkdf2 = require("easy-pbkdf2")();
	 * easyPbkdf2.findOptimalHashIterations(1000, .05, function(err, optimalHashIterations){
	 *     if ( err ) {
	 *         throw err;
	 *     }
	 *     console.log( "Default hash iterations for specified duration: " + optimalHashIterations ); 
	 * });
	 * 
	 * @param {Number} duration Number of milliseconds the hash function should take (higher is more secure). This number should be less than 
	 *     the duration between requests to your login server. A hash duration that is too high can result in a self-induced DDOS.  
	 * @param {String=} deviation The maximum amount (as a decimal percent) of deviation from the given duration. Defaults to 0.1. If the specified 
	 *     duration is 1000 and the deviation is .1, then the algorithm attempts to find a hash iterations that result in a duration between 900 - 1100ms (inclusive). Defaults to .1.
	 * @param {Function} callback fn( err, {Number} The number of hash iterations that approximate the given duration on similar hardware and load.
	 */
	"findOptimalHashIterations": function(duration, deviation, callback){
		if ( duration <= 0 ) {
			throw new Error("Durations must be greater than 0");
		}

		if ( isFunction( deviation ) || deviation == null ) {
			callback = callback || deviation;
			deviation = 0.1;
		}

		var deviation = duration * deviation,
			startingHashIterations = this.DEFAULT_HASH_ITERATIONS,
			testPassword = "EasyPbkdf2!";
		
		var bench = function ( iterations ) {
			this.DEFAULT_HASH_ITERATIONS = iterations;
			var start = process.hrtime();
			this.hash(testPassword, function( err, base64, salt ){
				if ( err ) {
					callback( err );
					return;
				}

				var timeDiff = process.hrtime( start ),
					// convert nanoseconds to milliseconds
					actualDuration = (timeDiff[0] * 1e9 + timeDiff[1])/1e6,
					diff = actualDuration - duration,
					absDiff = Math.abs( diff );
				
				if ( absDiff <= deviation ) {
					callback(null, iterations);
				}
				else {

					// We cannot allow actualDuration to be zero because Infinity will pay us a visit causing your computer will turn into a blackhole.
					// Increasing to 1 just causes the benchmark to run again with more iterations.
					if ( actualDuration === 0 ) {
						actualDuration = 1;
					}
					var ratio = actualDuration/duration || 1; 
					var newIterations = Math.round( iterations * (1 / ratio) );
					if ( newIterations === 0 ) {
						callback( new Error("A valid number of hash iterations could be found.") );
					}
					else{
						bench( newIterations );
					}
				}
			});
		}.bind(this);

		// V8 may optimize some stuff on its first run through, so we run everything once before benchmarking
		this.hash(testPassword, function( err, base64, salt ){
			bench(startingHashIterations);
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

function isFunction( obj ){
	return Object.prototype.toString.call( obj ) === "[object Function]";
}

function isString ( obj ) {
	return Object.prototype.toString.call( obj ) === "[object String]";
}