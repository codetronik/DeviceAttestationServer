package codetronik.server.attestation.service

import org.springframework.data.redis.core.RedisTemplate
import org.springframework.stereotype.Service
import java.util.*
import java.util.concurrent.TimeUnit

@Service
class MyService(private val redisTemplate: RedisTemplate<String, Any>) {
	fun createChallange() : String {
		val challengeId = UUID.randomUUID().toString()
		val challengeData = "Challenge-$challengeId"

		// Redis에 챌린지를 저장하고 3분 후에 자동으로 만료되게 설정
		redisTemplate.opsForValue().set(challengeId, challengeData, 3, TimeUnit.MINUTES)
		println("create challenge : $challengeData")
		return challengeId
	}


	fun sendCertChain(certChain: String) : Boolean {
		val verifier = Verifier()
		val certList = verifier.convertCertChain(certChain)

		val parser = AttestationExtensionContentParser()
		val keyDescription = parser.parseKeyDescription(certList.first())
		if (keyDescription == null) {
			return false
		}

		// 인증서 체인 검증
		if (!verifier.verifyCertChain(certList)) {
			println("Certificate verification failure")
			return false
		}

		// 챌린지 확인
		if (!verifier.verifyChallenge(keyDescription, redisTemplate)) {
			println("Challenge mismatch")
		}

		// 루팅 여부 확인
		if (!verifier.isTrustedDevice(keyDescription)) {
			println("Untrusted Device")
		}

		// 앱 위변조 확인
		if (!verifier.verifyCertificateFingerprint(keyDescription)) {
			println("Fingerprint mismatch")
		}

		return true
	}
}