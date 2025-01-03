package codetronik.server.attestation.service

import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DEROctetString
import java.io.ByteArrayInputStream
import java.security.cert.X509Certificate

data class KeyDescription(
	val attestationVersion: Int,
	val attestationSecurityLevel: Int,
	val keymasterVersion: Int,
	val keymasterSecurityLevel: Int,
	val attestationChallenge: String,
	val uniqueId: String,
	val softwareEnforced: AuthorizationList,
	val teeEnforced: AuthorizationList
)

data class AuthorizationList(
	val purpose: List<Int>?,
	val algorithm: Int?,
	val keySize: Int?,
	val digest: List<Int>?,
	val padding: List<Int>?,
	val ecCurve: Int?,
	val rsaPublicExponent: Long?,
	val mgfDigest: List<Int>?,
	val rollbackResistance: Boolean?,
	val earlyBootOnly: Boolean?,
	val activeDateTime: Long?,
	val originationExpireDateTime: Long?,
	val usageExpireDateTime: Long?,
	val usageCountLimit: Long?,
	val noAuthRequired: Boolean?,
	val userAuthType: Int?,
	val authTimeout: Int?,
	val allowWhileOnBody: Boolean?,
	val trustedUserPresenceRequired: Boolean?,
	val trustedConfirmationRequired: Boolean?,
	val unlockedDeviceRequired: Boolean?,
	val allApplications: Boolean?,
	val applicationId: String?,
	val creationDateTime: Long?,
	val origin: Int?,
	val rootOfTrust: RootOfTrust?,
	val osVersion: Int?,
	val osPatchLevel: Int?,
	val attestationApplicationId: ByteArray?,
	val attestationIdBrand: String?,
	val attestationIdDevice: String?,
	val attestationIdProduct: String?,
	val attestationIdSerial: String?,
	val attestationIdImei: String?,
	val attestationIdMeid: String?,
	val attestationIdManufacturer: String?,
	val attestationIdModel: String?,
	val vendorPatchLevel: Int?,
	val bootPatchLevel: Int?,
	val deviceUniqueAttestation: Boolean?
)

class AttestationExtensionContentParser {
	fun parseKeyDescription(certificate: X509Certificate): KeyDescription? {
		val extValue = certificate.getExtensionValue("1.3.6.1.4.1.11129.2.1.17") ?: run {
			println("OID not found in the certificate.")
			return null
		}

		val derObject = ASN1InputStream(ByteArrayInputStream(extValue)).use { asn1InputStream ->
			asn1InputStream.readObject()
		}

		val asn1Sequence = ASN1InputStream(ByteArrayInputStream((derObject as DEROctetString).octets)).use { octetInputStream ->
			octetInputStream.readObject() as ASN1Sequence
		}

		val elements = asn1Sequence.objects.toList() // Enumeration -> List 변환

		return KeyDescription(
			attestationVersion = (elements[0] as ASN1Integer).value.toInt(),
			attestationSecurityLevel = (elements[1] as ASN1Enumerated).value.toInt(),
			keymasterVersion = (elements[2] as ASN1Integer).value.toInt(),
			keymasterSecurityLevel = (elements[3] as ASN1Enumerated).value.toInt(),
			attestationChallenge = String((elements[4] as DEROctetString).octets),
			uniqueId = String((elements[5] as DEROctetString).octets),
			softwareEnforced = parseAuthorizationList(elements[6] as ASN1Sequence),
			teeEnforced = parseAuthorizationList(elements[7] as ASN1Sequence)
		)
	}

	private fun parseAuthorizationList(sequence: ASN1Sequence): AuthorizationList {
		val tag = AuthorizationListParser(sequence.objects.toList())

		return AuthorizationList(
			tag.purpose,
			tag.algorithm,
			tag.keySize,
			tag.digest,
			tag.padding,
			tag.ecCurve,
			tag.rsaPublicExponent,
			tag.mgfDigest,
			tag.rollbackResistance,
			tag.earlyBootOnly,
			tag.activeDateTime,
			tag.originationExpireDateTime,
			tag.usageExpireDateTime,
			tag.usageCountLimit,
			tag.noAuthRequired,
			tag.userAuthType,
			tag.authTimeout,
			tag.allowWhileOnBody,
			tag.trustedUserPresenceRequired,
			tag.trustedConfirmationRequired,
			tag.unlockedDeviceRequired,
			tag.allApplications,
			tag.applicationId,
			tag.creationDateTime,
			tag.origin,
			tag.rootOfTrust,
			tag.osVersion,
			tag.osPatchLevel,
			tag.attestationApplicationId,
			tag.attestationIdBrand,
			tag.attestationIdDevice,
			tag.attestationIdProduct,
			tag.attestationIdSerial,
			tag.attestationIdImei,
			tag.attestationIdMeid,
			tag.attestationIdManufacturer,
			tag.attestationIdModel,
			tag.vendorPatchLevel,
			tag.bootPatchLevel,
			tag.deviceUniqueAttestation
		)
	}
}