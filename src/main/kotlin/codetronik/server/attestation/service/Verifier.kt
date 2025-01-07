package codetronik.server.attestation.service

import org.springframework.data.redis.core.RedisTemplate
import java.io.ByteArrayInputStream
import java.security.KeyFactory
import java.security.PublicKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Base64

class Verifier {
	fun getGoogleRootPublicKey() : PublicKey {
		val encoded = Base64.getDecoder().decode("MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5UmAGMCAwEAAQ==")
		val keySpec = X509EncodedKeySpec(encoded)
		val keyFactory = KeyFactory.getInstance("RSA")

		return keyFactory.generatePublic(keySpec)
	}

	// 앱을 서명한 인증서의 지문이 일치하는지 확인
	// 인증서의 지문 : 인증서를 단순 SHA-256
	fun verifyCertificateFingerprint(keyDescription : KeyDescription) : Boolean {
		val attestationApplicationId = keyDescription.softwareEnforced.attestationApplicationId

		// 마지막 32바이트를 잘라내기
		val fingerprint = attestationApplicationId?.copyOfRange(attestationApplicationId.size - 32, attestationApplicationId.size)
		val fingerprintString = fingerprint?.joinToString("") { String.format("%02x", it) }

		// Fill in your fingerprint
		// $ apksigner verify --print-certs app-debug.apk
		val apkFingerprint = "e92796665ff2e9b82bc51c1cc86f20c0ea8b9d1dbd6d76ac81b4ca75f03953ad"
		if (fingerprintString != apkFingerprint) {
			return false
		}

		return true
	}

	fun isTrustedDevice(keyDescription : KeyDescription) : Boolean {
		// 0 : Verified
		// 1 : SelfSigned
		// 2 : Unverified
		// 3 : Failed
		println("Boot State : " + keyDescription.teeEnforced.rootOfTrust?.verifiedBootState)
		println("Device locked : " + keyDescription.teeEnforced.rootOfTrust?.deviceLocked)

		// 루팅 디바이스 체크
		if (keyDescription.teeEnforced.rootOfTrust?.verifiedBootState != 0) {
			return false
		}

		if (keyDescription.teeEnforced.rootOfTrust?.deviceLocked == false) {
			return false
		}

		return true
	}

	fun verifyChallenge(keyDescription : KeyDescription, redisTemplate : RedisTemplate<String, Any>?) : Boolean {
		val milliseconds = keyDescription.softwareEnforced.creationDateTime
		val instant = milliseconds?.let { Instant.ofEpochMilli(it) }
		val dateTime = instant?.atZone(ZoneId.systemDefault())

		val formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
		val formattedDateTime = dateTime?.format(formatter)

		println("Certificate creation time : $formattedDateTime")

		if (redisTemplate!!.opsForValue().get(keyDescription.attestationChallenge) == null) {
			return false
		}

		return true
	}

	fun convertCertChain(certChain: String) : MutableList<X509Certificate> {
		val byteArray = ByteArray(certChain.length / 2)
		for (i in byteArray.indices) {
			val index = i * 2
			val hexPair = certChain.substring(index, index + 2)
			byteArray[i] = hexPair.toInt(16).toByte()
		}

		val certificateFactory = CertificateFactory.getInstance("X.509")
		val certList = mutableListOf<X509Certificate>()
		val inputStream = ByteArrayInputStream(byteArray)
		while (inputStream.available() > 0) {
			val certificate = certificateFactory.generateCertificate(inputStream) as X509Certificate
			certList.add(certificate)
		}

		return certList
	}

	fun verifyCertChain(certList: MutableList<X509Certificate>) : Boolean {
		// 루트 인증서 검증
		val rootCertificate = certList.last()

		try {
			rootCertificate.verify(getGoogleRootPublicKey())
		} catch (e: Exception) {
			println("Failed to verify root certificate: ${e.message}")
			return false
		}

		// 밑에서 위로 체인 검증
		for (i in certList.size - 2 downTo 0) {
			val currentCert = certList[i]
			val issuerCert = certList[i + 1]
			try {
				// 현재 인증서의 무결성을 상위 인증서의 공개 키로 검증
				currentCert.verify(issuerCert.publicKey)
			} catch (e: Exception) {
				println("Failed to verify certificate at index $i: ${e.message}")
				return false
			}
		}

		return true
	}
}