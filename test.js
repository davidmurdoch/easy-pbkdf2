// very naive testing

var assert = require("assert"),
    easyPbkdf2 = require("./easy-pbkdf2")( {"DEFAULT_HASH_ITERATIONS": 64000, "SALT_SIZE": 64, "KEY_LENGTH": 512, "DIGEST": "sha512"} );

assert.strictEqual( easyPbkdf2.DEFAULT_HASH_ITERATIONS, 64000, "DEFAULT_HASH_ITERATIONS not set correctly");
assert.strictEqual( easyPbkdf2.SALT_SIZE, 64, "SALT_SIZE not set correctly");
assert.strictEqual( easyPbkdf2.KEY_LENGTH, 512, "KEY_LENGTH not set correctly");
assert.strictEqual( easyPbkdf2.DIGEST, "sha512", "DIGEST not set correctly");


easyPbkdf2.findOptimalHashIterations(1000, .2, function(err, optimalIterations){
    assert.ok( err == null, "findOptimalHashIterations returns error");
    assert.ok( optimalIterations > 0, "findOptimalHashIterations returns invalid optimalIterations.");
});


var testSalt = "400.sha256.2SxvTjFLU3OR1ELKJI8DSZBwuVBMlMfyrHCSfazf+8M3RDubvoqR0nxBfrQOZNBvCWRRP1Ysb0HG0vG5w+4A2NJwV0uWmvkcTkseAIgAI01fvD4zahEk+qMv0VyFUqnkOOgwHisc8YYEfS3sMokUz2mQFaru1UdUMPH99atPBFnmmpjZeaF0kmR824aRD2TLwYTMppcziWYVBITqVOcrt5MAW5UfeRnfMCf/9FHslMxCwn3z9f7vpkswSRWVb2ngHYZpbQTMcOqWreqBRzhlOKmqjDZz72ePGpCqn7lpOrafvEgMWs1YSZFk0f0JKfng+CSffnC3B/qFD3JeZTnnjw==";
var parsedSalt = { salt: '2SxvTjFLU3OR1ELKJI8DSZBwuVBMlMfyrHCSfazf+8M3RDubvoqR0nxBfrQOZNBvCWRRP1Ysb0HG0vG5w+4A2NJwV0uWmvkcTkseAIgAI01fvD4zahEk+qMv0VyFUqnkOOgwHisc8YYEfS3sMokUz2mQFaru1UdUMPH99atPBFnmmpjZeaF0kmR824aRD2TLwYTMppcziWYVBITqVOcrt5MAW5UfeRnfMCf/9FHslMxCwn3z9f7vpkswSRWVb2ngHYZpbQTMcOqWreqBRzhlOKmqjDZz72ePGpCqn7lpOrafvEgMWs1YSZFk0f0JKfng+CSffnC3B/qFD3JeZTnnjw==', iterations: 1024, digest: 'sha256' };
assert.deepEqual( easyPbkdf2.parseSalt(testSalt), parsedSalt, "Salt not parsed correctly");


var legacyTestSalt = "186a0.DuavD4wfEdbs4854zxCzkF35eXbEde6I2MlSsTJjBUU=";
var parsedLegacySalt = { salt: 'DuavD4wfEdbs4854zxCzkF35eXbEde6I2MlSsTJjBUU=', iterations: 100000, digest: 'sha1' };
assert.deepEqual( easyPbkdf2.parseSalt(legacyTestSalt), parsedLegacySalt, "Legacy salt not parsed correctly");


var salt = easyPbkdf2.generateSalt();
assert.ok( salt && salt.length > 0, "Sync salt not created correctly");


easyPbkdf2.findOptimalHashIterations(1000, .2, function(err, optimalIterations){
    assert.ok( err == null, "findOptimalHashIterations returns error");
    assert.ok( optimalIterations > 0, "findOptimalHashIterations returns invalid optimalIterations.");
});

easyPbkdf2.generateSalt( function( salt ){
    assert.ok( salt && salt.length > 0, "Async salt not created");

    assert.throws(function(){
        easyPbkdf2.generateSalt("notanumber");
    }, /explicitIterations must be an integer/, "generateSalt w/out a number does not throw");

    assert.throws(function(){
        easyPbkdf2.generateSalt( easyPbkdf2.DEFAULT_HASH_ITERATIONS - 1 )
    }, /explicitIterations cannot be less than \d+/, "generateSalt w/ an invalid number does not throw");

    var weakHash = easyPbkdf2.weakHash();
    assert.ok(weakHash && weakHash.length, "weakHash works as expected.");

    assert.strictEqual(easyPbkdf2.weakHash(["value"]), easyPbkdf2.weakHash(["value"]), "Generated weakHashes created with same seed value are not identical");

    var password = "password";
    easyPbkdf2.secureHash( password, function( err, hashed, salt ) {

        assert.ok( hashed && hashed.length > 0, "Hash not created");
        assert.ok( salt && salt.length > 0, "Salt not created");

		easyPbkdf2.verify( salt, hashed, password, function( err, valid ) {
			assert.strictEqual( valid, true, "verify returns incorrect result for matching data" );
		});

		easyPbkdf2.verify( salt, hashed, "not the password", function( err, valid ) {
			assert.strictEqual( valid, false, "Verify returns incorrect result for mismatched data" );
		});

        easyPbkdf2.secureHash( password, salt, function( err, secondHashed, _salt ){
            assert.strictEqual( secondHashed, hashed, "Hashing with identical salt and password does not work as expected" );
            assert.strictEqual( _salt, salt, "Salt changed and should havet");

            easyPbkdf2.secureHash( [], function(err){
                assert.ok(err instanceof Error, "invalid value does not emit error");

                assert.throws( function(){
                    easyPbkdf2.secureHash( "pass", "salt" );
                }, Error, "Missing callback does not throw");

                assert.throws( function(){
                    easyPbkdf2.secureHash( "pass", "salt", {} );
                }, Error, "Invalid callback does not throw");

                assert.ok(err instanceof Error, "Invalid value does not output error");

                var randomBytes = easyPbkdf2.random( 10 );
                assert.equal( randomBytes.length, 10, "Sync random returns incorrect randomBytes" );

                easyPbkdf2.random( 10, function( randomBytes ){
                    assert.equal( randomBytes.length, 10, "Async random returns incorrect randomBytes" );
                });
            });

        });
    });

});
