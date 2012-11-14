var crypto = require("crypto"),
    _ = require("lodash");

var EasyPbkdf2 = module.exports = function( options ) {
    if( !( this instanceof EasyPbkdf2 ) ){
        return new EasyPbkdf2( options );
    }

    if ( _.isPlainObject( options ) ) {
        _.each( options, function( value, key ){
            this[ key ] = value;
        }, this);
    }
}
EasyPbkdf2.prototype = {
	"DEFAULT_HASH_ITERATIONS": 5024,

	/**
	 * @constant Salt sizes throughout the system
	 */
	"SALT_SIZE": 256/8,

	/**
	 * Cranks out a collision resistant hash, relatively quickly.
	 *
	 * Not suitable for passwords, or sensitive information.
	 *
	 * Synchronous
	 *
	 * @param {String|Object} value The data to hash. The value is converted to
     *     a string via JSON.stringify(). Do NOT pass a function.
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
		if ( _.isFunction( callback ) ) {
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

        if ( !callback && _.isFunction( explicitIterations ) ) {
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
		if ( _.isFunction( callback ) ) {
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
     * If the salt param is ommitted, generates salt automatically
     * 
	 * Asynchronous
	 *
	 * @param {String} value MUST be a string, unless, of course, you want to explode.
	 * @param {String} salt (should include iterations). (optional)
	 * @param {Function} callback fn( err, {String} A secure hash (base64 encoded), salt w/ iterations )
	 */
	"hash": function( value, salt, callback ) {
        // if salt was not supplied, generate it now.
        if ( _.isFunction( salt ) || salt == null ) {
            callback = callback || salt;
            salt = this.generateSalt();
        }
        if ( !_.isFunction( callback ) ) {
            throw new Error("callback is required (as Function)");
        }
        if ( !value || typeof value !== "string" ) {
            callback(new Error("value is required (as String)"));
            return;
        }
		var keySize = 256,
			i = (salt).indexOf("."),
			iterations = parseInt( salt.substring( 0, i ), 16 );

		crypto.pbkdf2( value, salt.substring( i + 1 ), iterations, keySize, function( err, derivedKey ) {
            var base64;
            if ( !err ){
			    base64 = binaryToBase64( derivedKey );
            }
			callback( err, base64, salt );
		});
	}
};


EasyPbkdf2.EasyPbkdf2 = EasyPbkdf2;

function binaryToBase64( binary ){
    return new Buffer( binary, "binary" ).toString("base64");
}
