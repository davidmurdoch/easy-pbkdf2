// very naive testing

var assert = require("assert"),
    easyPbkdf2 = require("./easy-pbkdf2")( {"DEFAULT_HASH_ITERATIONS": 256, "SALT_SIZE": 128} );

assert.strictEqual( easyPbkdf2.DEFAULT_HASH_ITERATIONS, 256, "DEFAULT_HASH_ITERATIONS set correctly");
assert.strictEqual( easyPbkdf2.SALT_SIZE, 128, "SALT_SIZE set correctly");

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
    easyPbkdf2.secureHash( password, salt, function( hashed ) {
        assert.ok( hashed && hashed.length > 0, "Hash created");

        easyPbkdf2.secureHash( password, salt, function( secondHashed ){
            assert.strictEqual( secondHashed, hashed, "Hashing with identical salt and password works as expected" );

            var randomBytes = easyPbkdf2.random( 10 );
            assert.equal( randomBytes.length, 10, "Sync random returns correct randomBytes" );

            easyPbkdf2.random( 10, function( randomBytes ){
                assert.equal( randomBytes.length, 10, "Async random returns correct randomBytes" );

                console.log("done. all tests passes");
            });
        });
    });

});