#include <iostream>
#include <vector>
#include <unordered_map>
#include <omp.h>
#include <openssl/sha.h>  // OpenSSL library for cryptographic functions
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>

using namespace std;

// Function to hash a private key to a public key
string privateKeyToPublicKey(const string& privKeyHex) {
    vector<uint8_t> privKeyBytes(privKeyHex.size() / 2);
    for (size_t i = 0; i < privKeyHex.size(); i += 2) {
        privKeyBytes[i / 2] = stoi(privKeyHex.substr(i, 2), nullptr, 16);
    }

    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY* key = EC_KEY_new();
    EC_KEY_set_group(key, group);

    BIGNUM* privKeyBN = BN_bin2bn(privKeyBytes.data(), privKeyBytes.size(), nullptr);
    EC_KEY_set_private_key(key, privKeyBN);

    EC_POINT* pubKeyPoint = EC_POINT_new(group);
    EC_POINT_mul(group, pubKeyPoint, privKeyBN, nullptr, nullptr, nullptr);
    vector<uint8_t> pubKeyBytes(EC_POINT_point2oct(group, pubKeyPoint, POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr));
    EC_POINT_point2oct(group, pubKeyPoint, POINT_CONVERSION_UNCOMPRESSED, pubKeyBytes.data(), pubKeyBytes.size(), nullptr);

    string pubKeyHex;
    for (uint8_t byte : pubKeyBytes) {
        pubKeyHex += (byte < 16 ? "0" : "") + to_string(byte, nullptr, 16);
    }

    EC_POINT_free(pubKeyPoint);
    EC_KEY_free(key);
    EC_GROUP_free(group);
    BN_free(privKeyBN);

    return pubKeyHex;
}

// Function to compute public key for all possible private keys in a range
bool bsgs(const string& targetPubKeyHex, const string& startHex, const string& endHex) {
    // Parse start and end hex into integer
    BIGNUM* start = nullptr;
    BIGNUM* end = nullptr;
    BN_hex2bn(&start, startHex.c_str());
    BN_hex2bn(&end, endHex.c_str());

    BIGNUM* current = BN_new();
    BN_copy(current, start);

    unordered_map<string, BIGNUM*> babySteps;

    // Baby-step: Compute public keys for small private keys
    #pragma omp parallel
    {
        #pragma omp single
        {
            while (BN_cmp(current, end) <= 0) {
                string privKeyHex = BN_bn2hex(current);
                string pubKeyHex = privateKeyToPublicKey(privKeyHex);
                babySteps[pubKeyHex] = BN_dup(current);

                // Increment current
                BN_add(current, current, BN_value_one());
            }
        }
    }

    // Giant-step: Compare with target public key
    for (const auto& entry : babySteps) {
        if (entry.first == targetPubKeyHex) {
            cout << "Private key found: " << BN_bn2hex(entry.second) << endl;
            BN_free(start);
            BN_free(end);
            BN_free(current);
            for (auto& pair : babySteps) {
                BN_free(pair.second);
            }
            return true;
        }
    }

    BN_free(start);
    BN_free(end);
    BN_free(current);
    for (auto& pair : babySteps) {
        BN_free(pair.second);
    }

    cout << "Private key NOT found" << endl;
    return false;
}

int main() {
    string targetAddress = "target_address";
    string startHex = "00000000000000000000000000000000";
    string endHex = "ffffffffffffffffffffffffffffffff";

    string targetPubKeyHex = privateKeyToPublicKey("dummy_private_key");

    bool found = bsgs(targetPubKeyHex, startHex, endHex);
    return 0;
}
