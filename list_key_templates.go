package main

import (
	"fmt"

	// Import the primitive packages that contain the templates you want to list
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/daead"
	"github.com/tink-crypto/tink-go/v2/hybrid"
	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/mac"
	"github.com/tink-crypto/tink-go/v2/prf"
	"github.com/tink-crypto/tink-go/v2/proto/tink_go_proto" // Needed if you want to inspect template details
	"github.com/tink-crypto/tink-go/v2/signature"
	"github.com/tink-crypto/tink-go/v2/streamingaead"
)

// Define a map to associate names with template functions
var supportedTemplates = map[string]func() *tink_go_proto.KeyTemplate{
	// MAC
	"AES_CMAC":              mac.AESCMACTag128KeyTemplate,
	"HMAC_SHA256_128BITTAG": mac.HMACSHA256Tag128KeyTemplate,
	"HMAC_SHA256_256BITTAG": mac.HMACSHA256Tag256KeyTemplate,
	"HMAC_SHA512_256BITTAG": mac.HMACSHA512Tag256KeyTemplate,
	"HMAC_SHA512_512BITTAG": mac.HMACSHA512Tag512KeyTemplate,

	// AEAD
	"AES128_GCM":             aead.AES128GCMKeyTemplate,
	"AES256_GCM":             aead.AES256GCMKeyTemplate,
	"AES256_GCM_RAW":         aead.AES256GCMNoPrefixKeyTemplate,
	"AES128_CTR_HMAC_SHA256": aead.AES128CTRHMACSHA256KeyTemplate,
	"AES256_CTR_HMAC_SHA256": aead.AES256CTRHMACSHA256KeyTemplate,
	"AES128_GCM_SIV":         aead.AES128GCMSIVKeyTemplate,
	"AES256_GCM_SIV":         aead.AES256GCMSIVKeyTemplate,
	"AES256_GCM_SIV_RAW":     aead.AES256GCMSIVNoPrefixKeyTemplate,
	"CHACHA20_POLY1305":      aead.ChaCha20Poly1305KeyTemplate,
	"XCHACHA20_POLY1305":     aead.XChaCha20Poly1305KeyTemplate,

	// Deterministic AEAD
	"AES_SIV": daead.AESSIVKeyTemplate,

	// Digital Signatures
	"ECDSA_P256":                  signature.ECDSAP256KeyTemplate,
	"ECDSA_P256_NO_PREFIX":        signature.ECDSAP256KeyWithoutPrefixTemplate,
	"ECDSA_P256_RAW":              signature.ECDSAP256RawKeyTemplate,
	"ECDSA_P384_NO_PREFIX":        signature.ECDSAP384KeyWithoutPrefixTemplate,
	"ECDSA_P384_SHA384":           signature.ECDSAP384SHA384KeyTemplate,
	"ECDSA_P384_SHA384_NO_PREFIX": signature.ECDSAP384SHA384KeyWithoutPrefixTemplate,
	"ECDSA_P384_SHA512":           signature.ECDSAP384SHA512KeyTemplate,
	"ECDSA_P521":                  signature.ECDSAP521KeyTemplate,
	"ECDSA_P521_NO_PREFIX":        signature.ECDSAP521KeyWithoutPrefixTemplate,
	"ED25519":                     signature.ED25519KeyTemplate,
	"ED25519_NO_PREFIX":           signature.ED25519KeyWithoutPrefixTemplate,

	"RSA_SSA_PKCS1_3072_SHA256_F4": signature.RSA_SSA_PKCS1_3072_SHA256_F4_Key_Template,
	"RSA_SSA_PKCS1_3072_SHA512_F4": signature.RSA_SSA_PKCS1_4096_SHA512_F4_Key_Template,
	// "RSA_SSA_PSS_3072_SHA256_SHA256_32_F4": signature.RSA_SSA_PSS_3072_SHA256_SHA256_32_F4_Key_Template ,
	// "RSA_SSA_PSS_4096_SHA512_SHA512_64_F4": signature.RSA_SSA_PSS_4096_SHA512_SHA512_64_F4_Key_Template ,

	// Hybrid Encryption
	"ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM":             hybrid.ECIESHKDFAES128GCMKeyTemplate,
	"ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256": hybrid.ECIESHKDFAES128CTRHMACSHA256KeyTemplate,
	// DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM // Example, check exact function name if available
	// DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM // Example, check exact function name if available
	// DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305 // Example, check exact function name if available

	// PRF
	"HMAC_SHA256_PRF": prf.HMACSHA256PRFKeyTemplate,
	"HMAC_SHA512_PRF": prf.HMACSHA512PRFKeyTemplate,
	"AES_CMAC_PRF":    prf.AESCMACPRFKeyTemplate,
	"HKDF_SHA256":     prf.HKDFSHA256PRFKeyTemplate,

	// Streaming AEAD
	"AES128_GCM_HKDF_4KB":        streamingaead.AES128GCMHKDF4KBKeyTemplate,
	"AES256_GCM_HKDF_4KB":        streamingaead.AES256GCMHKDF4KBKeyTemplate,
	"AES128_GCM_HKDF_1MB":        streamingaead.AES128GCMHKDF1MBKeyTemplate,
	"AES256_GCM_HKDF_1MB":        streamingaead.AES256GCMHKDF1MBKeyTemplate,
	"AES128_CTR_HMAC_SHA256_4KB": streamingaead.AES128CTRHMACSHA256Segment4KBKeyTemplate,
	"AES256_CTR_HMAC_SHA256_4KB": streamingaead.AES256CTRHMACSHA256Segment4KBKeyTemplate,
	"AES128_CTR_HMAC_SHA256_1MB": streamingaead.AES128CTRHMACSHA256Segment1MBKeyTemplate,
	"AES256_CTR_HMAC_SHA256_1MB": streamingaead.AES256CTRHMACSHA256Segment1MBKeyTemplate,

	// JWT
	"ES256":             jwt.ES256Template,
	"ES384":             jwt.ES384Template,
	"ES512":             jwt.ES512Template,
	"HS256":             jwt.HS256Template,
	"HS384":             jwt.HS384Template,
	"HS512":             jwt.HS512Template,
	"PS256_2048_F4":     jwt.PS256_2048_F4_Key_Template,
	"PS256_3072_F4":     jwt.PS256_3072_F4_Key_Template,
	"PS384_3072_F4":     jwt.PS384_3072_F4_Key_Template,
	"PS512_4096_F4":     jwt.PS512_4096_F4_Key_Template,
	"RS256_2048_F4":     jwt.RS256_2048_F4_Key_Template,
	"RS256_3072_F4":     jwt.RS256_3072_F4_Key_Template,
	"RS384_3072_F4":     jwt.RS384_3072_F4_Key_Template,
	"RS512_4096_F4":     jwt.RS512_4096_F4_Key_Template,
	"ES256_RAW":         jwt.RawES256Template,
	"ES384_RAW":         jwt.RawES384Template,
	"ES512_RAW":         jwt.RawES512Template,
	"HS256_RAW":         jwt.RawHS256Template,
	"HS384_RAW":         jwt.RawHS384Template,
	"HS512_RAW":         jwt.RawHS512Template,
	"PS256_2048_F4_RAW": jwt.RawPS256_2048_F4_Key_Template,
	"PS256_3072_F4_RAW": jwt.RawPS256_3072_F4_Key_Template,
	"PS384_3072_F4_RAW": jwt.RawPS384_3072_F4_Key_Template,
	"PS512_4096_F4_RAW": jwt.RawPS512_4096_F4_Key_Template,
	"RS256_2048_F4_RAW": jwt.RawRS256_2048_F4_Key_Template,
	"RS256_3072_F4_RAW": jwt.RawRS256_3072_F4_Key_Template,
	"RS384_3072_F4_RAW": jwt.RawRS384_3072_F4_Key_Template,
	"RS512_4096_F4_RAW": jwt.RawRS512_4096_F4_Key_Template,
}

func listKeyTemplates(*cliOpts) error {
	fmt.Println("The following key template names are recognized:")
	// Iterate through the map keys (names) and print them
	// You could sort them alphabetically if desired.
	for name := range supportedTemplates {
		fmt.Printf("  %s\n", name)
	}

	return nil
}
