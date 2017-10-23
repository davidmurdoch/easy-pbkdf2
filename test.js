// very naive testing

var assert = require("assert"),
    easyPbkdf2 = require("./easy-pbkdf2")( {"DEFAULT_HASH_ITERATIONS": 256, "SALT_SIZE": 128, "KEY_LENGTH": 1024, "MAX_PASSWORD_LENGTH": 2048} );

assert.strictEqual( easyPbkdf2.DEFAULT_HASH_ITERATIONS, 256, "DEFAULT_HASH_ITERATIONS set correctly");
assert.strictEqual( easyPbkdf2.SALT_SIZE, 128, "SALT_SIZE set correctly");
assert.strictEqual( easyPbkdf2.KEY_LENGTH, 1024, "KEY_LENGTH set correctly");
assert.strictEqual( easyPbkdf2.MAX_PASSWORD_LENGTH, 2048, "MAX_PASSWORD_LENGTH set correctly");

var salt = easyPbkdf2.generateSalt();
assert.ok( salt && salt.length > 0, "Sync salt created");

easyPbkdf2.generateSalt( function( salt ){
    assert.ok( salt && salt.length > 0, "Async salt created");

    assert.throws(function(){
        easyPbkdf2.generateSalt("notanumber");
    }, /explicitIterations must be an integer/, "generateSalt w/out a number throws");

    assert.throws(function(){
        easyPbkdf2.generateSalt( easyPbkdf2.DEFAULT_HASH_ITERATIONS - 1 )
    }, /explicitIterations cannot be less than \d+/, "generateSalt w/ an invalid number throws");

    var weakHash = easyPbkdf2.weakHash();
    assert.ok(weakHash && weakHash.length, "weakHash works as expected.");

    assert.strictEqual(easyPbkdf2.weakHash(["value"]), easyPbkdf2.weakHash(["value"]), "Generated weakHashes created with same seed value are identical");

    var password = "password";
    easyPbkdf2.secureHash( password, function( err, hashed, salt ) {

        assert.ok( hashed && hashed.length > 0, "Hash created");
        assert.ok( salt && salt.length > 0, "Salt created");

		easyPbkdf2.verify( salt, hashed, password, function( err, valid ) {
			assert.strictEqual( valid, true, "verify returns correct result for matching data" );
		});

		easyPbkdf2.verify( salt, hashed, "not the password", function( err, valid ) {
			assert.strictEqual( valid, false, "Verify returns correct result for mismatched data" );
		});

        easyPbkdf2.secureHash( password, salt, function( err, secondHashed, _salt ){
            assert.strictEqual( secondHashed, hashed, "Hashing with identical salt and password works as expected" );
            assert.strictEqual( _salt, salt, "Salt did not change");

            easyPbkdf2.secureHash( [], function(err){
                assert.ok(err instanceof Error, "invalid value emits error");

                assert.throws( function(){
                    easyPbkdf2.secureHash( "pass", "salt" );
                }, Error, "Missing callback throws");

                assert.throws( function(){
                    easyPbkdf2.secureHash( "pass", "salt", {} );
                }, Error, "invliad callback throws");

                assert.ok(err instanceof Error, "invalid value emits error");

                var randomBytes = easyPbkdf2.random( 10 );
                assert.equal( randomBytes.length, 10, "Sync random returns correct randomBytes" );

                easyPbkdf2.random( 10, function( randomBytes ){
                    assert.equal( randomBytes.length, 10, "Async random returns correct randomBytes" );

                    easyPbkdf2.MAX_PASSWORD_LENGTH = 7
                    easyPbkdf2.secureHash( "password", "salt", function(err){
                        assert.ok( err instanceof Error, "Hashing a too-long password emits error" );
                        assert.equal( err.message, "Password exceeds maximum length of 7", "Hashing a too-long password has correct error message" );

                        easyPbkdf2.MAX_PASSWORD_LENGTH = 8
                        easyPbkdf2.secureHash( "password", "salt", function(err){
                            assert.ok( !err, "No error when password length is at the limit" );
                            assert.ok( hashed && hashed.length > 0, "Hash created when password is at the length limit");
                            assert.ok( salt && salt.length > 0, "Salt created when password is at the length limit");

                            easyPbkdf2.MAX_PASSWORD_LENGTH = 7
                            easyPbkdf2.verify( salt, hashed, password, function( err, valid ) {
                                assert.ok( err instanceof Error, "Verifying a too-long password emits error" );
                                assert.equal( err.message, "Password exceeds maximum length of 7", "Verifying a too-long password has correct error message" );
                                assert.ok( !valid, "Verify returns correct result for too-long password");

                                easyPbkdf2.MAX_PASSWORD_LENGTH = 8
                                easyPbkdf2.verify( salt, hashed, password, function( err, valid ) {
                                    assert.ok( !err, "No error when verifying password at the limit" );
                                    assert.ok( valid, "Verify returns correct result for password at the length limit");

                                    console.log("done. all tests passes");
                                });
                            });
                        });
                    });
                });
            });

        });
    });

});
