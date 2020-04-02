#include "mococrw/ecies.h"
#include "mococrw/symmetric_crypto.h"
#include "mococrw/openssl_wrap.h"
#include "mococrw/util.h"

namespace  {
enum class Mode {
    Decryption = 0,
    Encryption
};
}

namespace mococrw {

class ECIESCtxBuilder::Impl
{
public:
    Impl() : _pubKey(nullptr), _privKey(nullptr) {};
    ~Impl() = default;

    void setKDF(std::shared_ptr<KeyDerivationFunction> kdf)
    {
        _kdf = kdf;
    }

    void setMacKeySize(size_t keySize)
    {
        _macKeySize = keySize;
    }

    void setMacFactoryFunction(std::function<std::unique_ptr<MessageAuthenticationCode>(
                                               const std::vector<uint8_t>&)> func)
    {
        _macFactoryFunction = func;
    }

    void setSymmetricCipherKeySize(size_t keySize)
    {
        _symmetricKeySize = keySize;
    }

    void setSymmetricCipherFactoryFunction(std::function<std::unique_ptr<SymmetricCipherI>(
                                                           const std::vector<uint8_t>&)> func)
    {
        _symmetricCipherFactoryFunction = func;
    }

    void setKDFSalt(std::vector<uint8_t> kdfSalt)
    {
        _kdfSalt = std::move(kdfSalt);
    }

    void setMACSalt(std::vector<uint8_t> macSalt)
    {
        _macSalt = std::move(macSalt);
    }

    void setDefaultKdf()
    {
        setKDF(std::make_shared<X963KDF>(openssl::DigestTypes::SHA512));
    }

    void setDefaultMac()
    {
        setMacFactoryFunction([](const std::vector<uint8_t> &key) -> std::unique_ptr<MessageAuthenticationCode> {
            return std::make_unique<mococrw::HMAC>(openssl::DigestTypes::SHA512, key);
        });

        setMacKeySize(512 / 8);
    }

    void setDefaultSymmetricCipherFactoryFunction(Mode encryptionMode)
    {
        const SymmetricCipherMode mode = SymmetricCipherMode::CBC;
        const SymmetricCipherKeySize keySize = SymmetricCipherKeySize::S_256;
        const SymmetricCipherPadding padding = SymmetricCipherPadding::PKCS;
        const std::vector<uint8_t> zeroIV = std::vector<uint8_t>(AESCipherBuilder::getDefaultIVLength(mode));

        if (encryptionMode == Mode::Encryption) {
            setSymmetricCipherFactoryFunction([zeroIV](const std::vector<uint8_t> &key) -> std::unique_ptr<AESCipher> {
                return AESCipherBuilder(mode, keySize, key).setIV(zeroIV).setPadding(padding).buildEncryptor();
            });
        } else {
            setSymmetricCipherFactoryFunction([zeroIV](const std::vector<uint8_t> &key) -> std::unique_ptr<AESCipher> {
                return AESCipherBuilder(mode, keySize, key).setIV(zeroIV).setPadding(padding).buildDecryptor();
            });
        }

        setSymmetricCipherKeySize(256 / 8);
    }

    void checkForRequiredParameters(Mode mode)
    {
        /* Check for all inputs to be set */
        if (!_kdf) {
            setDefaultKdf();
        }
        if ((_macFactoryFunction && !_macKeySize) || (!_macFactoryFunction && _macKeySize)) {
            throw MoCOCrWException("MAC parameters are incomplete. Either the factory function or the key size is set"
                                   ", but not both!");
        }
        if (!_macFactoryFunction || !_macKeySize) {
            setDefaultMac();
        }
        if ((_symmetricCipherFactoryFunction && !_symmetricKeySize)
                || (!_symmetricCipherFactoryFunction && _symmetricKeySize)) {
            throw MoCOCrWException("Symmetric cipher parameters are incomplete. Either the factory function or the key "
                                   "size is set, but not both!");
        }
        if (!_symmetricCipherFactoryFunction || !_symmetricKeySize) {
            setDefaultSymmetricCipherFactoryFunction(mode);
        }
        /* The salts for kdf and mac are optional */
    }

    std::shared_ptr<KeyDerivationFunction> _kdf;
    size_t _macKeySize = 0;
    std::function<std::unique_ptr<MessageAuthenticationCode> (const std::vector<uint8_t> &)> _macFactoryFunction;
    size_t _symmetricKeySize = 0;
    std::function<std::unique_ptr<SymmetricCipherI> (const std::vector<uint8_t> &)> _symmetricCipherFactoryFunction;
    std::vector<uint8_t> _kdfSalt;
    std::vector<uint8_t> _macSalt;
    AsymmetricPublicKey _pubKey;
    AsymmetricPrivateKey _privKey;

};

class ECIESImpl
{
public:
    ECIESImpl(const ECIESCtxBuilder &ctxBuilder)
        : _kdf(ctxBuilder._impl->_kdf),
          _macKeySize(ctxBuilder._impl->_macKeySize),
          _macFactoryFunc(ctxBuilder._impl->_macFactoryFunction),
          _mac(nullptr),
          _symmetricKeySize(ctxBuilder._impl->_symmetricKeySize),
          _symCipherFactoryFunc(ctxBuilder._impl->_symmetricCipherFactoryFunction),
          _kdfSalt(ctxBuilder._impl->_kdfSalt),
          _macSalt(ctxBuilder._impl->_macSalt),
          _symcryptor(nullptr)    {}

    virtual ~ECIESImpl()
    {

    }

protected:
    void createKeysAndInstantiateMacAndSymCipher(std::vector<uint8_t> sharedSecret)
    {
        utility::Finally sharedSecret_deleter([&sharedSecret]() {
            utility::vectorCleanse(sharedSecret);
        });

        std::vector<uint8_t> result;
        utility::Finally result_deleter([&result]() {
            utility::vectorCleanse(result);
        });

        result = _kdf->deriveKey(sharedSecret, _macKeySize + _symmetricKeySize, _kdfSalt);

        std::vector<uint8_t> _key_encrypt(_symmetricKeySize);
        utility::Finally key_encrypt_deleter([&_key_encrypt]() {
            utility::vectorCleanse(_key_encrypt);
        });

        std::vector<uint8_t> _key_mac(_macKeySize);
        utility::Finally key_mac_deleter([&_key_mac]() {
            utility::vectorCleanse(_key_mac);
        });

        /* Copy first part (encryption key) */
        std::copy(result.begin(), result.begin() + _symmetricKeySize, _key_encrypt.begin());

        /* Copy second part (mac key) */
        std::copy(result.begin() + _symmetricKeySize, result.end(), _key_mac.begin());

        /* We have calculated the MAC key now -> set it */
        _mac = _macFactoryFunc(_key_mac);

        /* initialize the de/encryptor */
        _symcryptor = _symCipherFactoryFunc(_key_encrypt);

    }

    const std::shared_ptr<KeyDerivationFunction> _kdf;
    const size_t _macKeySize;
    std::function<std::unique_ptr<MessageAuthenticationCode> (const std::vector<uint8_t> &)> _macFactoryFunc;
    std::unique_ptr<MessageAuthenticationCode> _mac;
    const size_t _symmetricKeySize;
    std::function<std::unique_ptr<SymmetricCipherI>(const std::vector<uint8_t> &)> _symCipherFactoryFunc;
    const std::vector<uint8_t> _kdfSalt;
    const std::vector<uint8_t> _macSalt;

    std::unique_ptr<SymmetricCipherI> _symcryptor;
    std::vector<uint8_t> _mac_value;
    bool _isFinished = false;
};

class ECIESEncryptionCtx::Impl : public ECIESImpl
{
public:
    Impl(const ECIESCtxBuilder &ctxBuilder)
        : ECIESImpl(ctxBuilder), _ephemeralKey(nullptr)
    {
        auto shared_secret = createEphemeralKeyAndSharedSecret(ctxBuilder._impl->_pubKey);
        createKeysAndInstantiateMacAndSymCipher(std::move(shared_secret));
    }

    ~Impl() {};

    void update(const std::vector<uint8_t> &message)
    {
        /* Encrypt the message */
        if (!_symcryptor) {
            throw MoCOCrWException("Encryption context is not initialized.");
        }

        if (_isFinished) {
            throw MoCOCrWException("update() is invoked after finish is called.");
        }

        _symcryptor->update(message);
    }

    std::vector<uint8_t> finish()
    {
        if (_isFinished) {
            throw MoCOCrWException("finish() is invoked twice.");
        }

        std::vector<uint8_t> result;

        /* Finish the encryption */
        result = _symcryptor->finish();
        _mac->update(result);

        /* Calculate the MAC */
        _mac->update(_macSalt);
        _mac_value = _mac->finish();

        _isFinished = true;

        return result;
    }

    AsymmetricPublicKey getEphemeralKey()
    {
        /* Return the ephemeral key */
        return _ephemeralKey;
    }

    std::vector<uint8_t> getMAC()
    {
        if (!_isFinished) {
            throw MoCOCrWException("getMAC() is invoked before finish is called.");
        }
        /* Return the MAC. Finish has to be invoked first */
        return _mac_value;
    }

private:
    std::vector<uint8_t> createEphemeralKeyAndSharedSecret(const AsymmetricPublicKey &pubKey)
    {
        // 1. Get the parameters from the public key and generate a new key based on it
        AsymmetricKeypair key(AsymmetricKeypair::generate(*pubKey.getKeySpec().get()));

        _ephemeralKey = AsymmetricPublicKey(key);

        // 2. Derive shared secret
        return openssl::_EVP_derive_key(pubKey.internal(), key.internal());
    }

    AsymmetricPublicKey _ephemeralKey;

};

class ECIESDecryptionCtx::Impl : public ECIESImpl
{
public:
    Impl(const ECIESCtxBuilder &ctxBuilder)
        : ECIESImpl(ctxBuilder),
         _privKey(ctxBuilder._impl->_privKey)
    {}

    void update(const std::vector<uint8_t>& message)
    {
        if (_isFinished) {
            throw MoCOCrWException("update() is invoked after finish was invoked.");
        }

        if (!_ephKeyIsSet) {
            throw MoCOCrWException("No ephemeral key is set.");
        }
        _symcryptor->update(message);

        /* also set the ciphertext for mac calculation */
        _mac->update(message);
    }

    std::vector<uint8_t> finish()
    {
        if (_isFinished) {
            throw MoCOCrWException("finish() is invoked twice.");
        }

        if (!_ephKeyIsSet) {
            throw MoCOCrWException("No ephemeral key is set.");
        }

        if (!_macIsSet) {
            throw MoCOCrWException("Set the MAC before invoking finish.");
        }

        /* Calculate the MAC (the ciphertext for mac is set in update) */
        _mac->update(_macSalt);
        /* We don't care for the result as we invoke verify */
        _mac->finish();
        _mac->verify(_tag);

        std::vector<uint8_t> result;

        /* Finish the decryption */
        result = _symcryptor->finish();

        _isFinished = true;

        return result;
    }

    void setEphemeralKey(const AsymmetricPublicKey& ephKey)
    {
        /* calculate the keys for encryption and MAC */
        auto sharedSecret = openssl::_EVP_derive_key(ephKey.internal(), _privKey.internal());
        createKeysAndInstantiateMacAndSymCipher(std::move(sharedSecret));

        _ephKeyIsSet = true;
    }

    void setMAC(const std::vector<uint8_t>& tag)
    {
        _tag = tag;
        _macIsSet = true;
    }

private:
    AsymmetricPrivateKey _privKey;
    std::vector<uint8_t> _tag;
    bool _ephKeyIsSet = false;
    bool _macIsSet = false;
};


ECIESEncryptionCtx::ECIESEncryptionCtx(const ECIESCtxBuilder &ctxBuilder)
{
    _impl = std::make_unique<ECIESEncryptionCtx::Impl>(ctxBuilder);
}

ECIESEncryptionCtx::~ECIESEncryptionCtx() = default;

void ECIESEncryptionCtx::update(const std::vector<uint8_t> &message)
{
    _impl->update(message);
}

std::vector<uint8_t> ECIESEncryptionCtx::finish()
{
    return _impl->finish();
}

AsymmetricPublicKey ECIESEncryptionCtx::getEphemeralKey()
{
    return _impl->getEphemeralKey();
}

std::vector<uint8_t> ECIESEncryptionCtx::getMAC()
{
    return _impl->getMAC();
}

ECIESDecryptionCtx::ECIESDecryptionCtx(const ECIESCtxBuilder &ctxBuilder)
{
    _impl = std::make_unique<ECIESDecryptionCtx::Impl>(ctxBuilder);
}

ECIESDecryptionCtx::~ECIESDecryptionCtx() = default;

void ECIESDecryptionCtx::update(const std::vector<uint8_t> &message)
{
    _impl->update(message);
}

std::vector<uint8_t> ECIESDecryptionCtx::finish()
{
    return _impl->finish();
}

void ECIESDecryptionCtx::setEphemeralKey(const AsymmetricPublicKey &ephKey)
{
    _impl->setEphemeralKey(ephKey);
}

void ECIESDecryptionCtx::setMAC(const std::vector<uint8_t> &tag)
{
    _impl->setMAC(tag);
}

ECIESCtxBuilder::ECIESCtxBuilder()
{
    _impl = std::make_unique<ECIESCtxBuilder::Impl>();
}

ECIESCtxBuilder::~ECIESCtxBuilder() {}

ECIESCtxBuilder &ECIESCtxBuilder::setKDF(std::shared_ptr<KeyDerivationFunction> kdf)
{
    _impl->setKDF(kdf);
    return *this;
}

ECIESCtxBuilder &ECIESCtxBuilder::setMacKeySize(size_t keySize)
{
    _impl->setMacKeySize(keySize);
    return *this;
}

ECIESCtxBuilder &ECIESCtxBuilder::setMacFactoryFunction(std::function<std::unique_ptr<MessageAuthenticationCode>
                                                        (const std::vector<uint8_t> &)> func)
{
    _impl->setMacFactoryFunction(func);
    return *this;
}

ECIESCtxBuilder &ECIESCtxBuilder::setSymmetricCipherKeySize(size_t keySize)
{
    _impl->setSymmetricCipherKeySize(keySize);
    return *this;
}

ECIESCtxBuilder &ECIESCtxBuilder::setSymmetricCipherFactoryFunction(std::function<std::unique_ptr<SymmetricCipherI>
                                                                    (const std::vector<uint8_t> &)> func)
{
    _impl->setSymmetricCipherFactoryFunction(func);
    return *this;
}

ECIESCtxBuilder &ECIESCtxBuilder::setKDFSalt(std::vector<uint8_t> kdfSalt)
{
    _impl->setKDFSalt(std::move(kdfSalt));
    return *this;
}

ECIESCtxBuilder &ECIESCtxBuilder::setMACSalt(std::vector<uint8_t> macSalt)
{
    _impl->setMACSalt(std::move(macSalt));
    return *this;
}

std::unique_ptr<ECIESEncryptionCtx> ECIESCtxBuilder::buildEncryptionCtx(AsymmetricPublicKey bobsKey)
{
    _impl->_pubKey = std::move(bobsKey);
    _impl->checkForRequiredParameters(Mode::Encryption);

    /* We cannot use std::make_unique because:
     * - The constructor of ECIESEncryptionCtx is private
     * - The ECIESEncryptionCtxBuilder is a friend of ECIESEncryptionCtx
     * - If we call std::make_unique (which is a function call), we invoke the constructor from outside of the
     *   ECIESEncryptionCtxBuilder. Thus the call is not allowed as it is private (friend is not transitive)
     */
    auto retVal = new ECIESEncryptionCtx(*this);
    if (!retVal) {
        throw MoCOCrWException("Error initialising ECIESEncryptionCtx");
    }

    return std::unique_ptr<ECIESEncryptionCtx>(retVal);
}

std::unique_ptr<ECIESEncryptionCtx> ECIESCtxBuilder::buildEncryptionCtx(X509Certificate bobsCert)
{
    return buildEncryptionCtx(bobsCert.getPublicKey());
}

std::unique_ptr<ECIESDecryptionCtx> ECIESCtxBuilder::buildDecryptionCtx(AsymmetricPrivateKey bobsKey)
{
    _impl->_privKey = std::move(bobsKey);
    _impl->checkForRequiredParameters(Mode::Decryption);

    /* We cannot use std::make_unique because:
     * - The constructor of ECIESDecryptionCtx is private
     * - The ECIESDecryptionCtxBuilder is a friend of ECIESDecryptionCtx
     * - If we call std::make_unique (which is a function call), we invoke the constructor from outside of the
     *   ECIESDecryptionCtxBuilder. Thus the call is not allowed as it is private (friend is not transitive)
     */
    auto retVal = new ECIESDecryptionCtx(*this);
    if (!retVal) {
        throw MoCOCrWException("Error initialising ECIESDecryptionCtx");
    }

    return std::unique_ptr<ECIESDecryptionCtx>(retVal);
}
} //mococrw
