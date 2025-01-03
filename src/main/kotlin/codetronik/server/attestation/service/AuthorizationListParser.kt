package codetronik.server.attestation.service

import org.bouncycastle.asn1.*

data class RootOfTrust(
	val verifiedBootKey: String,
	val deviceLocked: Boolean,
	val verifiedBootState: Int,
	val verifiedBootHash: String?
)

class AuthorizationListParser(sequenceObjects: List<Any>) {
	private val tagMap = mutableMapOf<Int, Any>()

	init {
		sequenceObjects.forEach {
			val taggedObject = it as ASN1TaggedObject
			tagMap[taggedObject.tagNo] = taggedObject.`object`
		}
	}

	private enum class TagIndex(val index: Int) {
		Purpose(1),
		Algorithm(2),
		KeySize(3),
		Digest(5),
		Padding(6),
		EcCurve(10),
		RsaPublicExponent(200),
		MgfDigest(203),
		RollbackResistance(303),
		EarlyBootOnly(305),
		ActiveDateTime(400),
		OriginationExpireDateTime(401),
		UsageExpireDateTime(402),
		UsageCountLimit(405),
		NoAuthRequired(503),
		UserAuthType(504),
		AuthTimeout(505),
		AllowWhileOnBody(506),
		TrustedUserPresenceRequired(507),
		TrustedConfirmationRequired(508),
		UnlockedDeviceRequired(509),
		AllApplications(600),
		ApplicationId(601),
		CreationDateTime(701),
		Origin(702),
		RootOfTrust(704),
		OsVersion(705),
		OsPatchLevel(706),
		AttestationApplicationId(709),
		AttestationIdBrand(710),
		AttestationIdDevice(711),
		AttestationIdProduct(712),
		AttestationIdSerial(713),
		AttestationIdImei(714),
		AttestationIdMeid(715),
		AttestationIdManufacturer(716),
		AttestationIdModel(717),
		VendorPatchLevel(718),
		BootPatchLevel(719),
		DeviceUniqueAttestation(720)
	}

	val purpose get() = (tagMap[TagIndex.Purpose.index] as? ASN1Set)?.objects?.toList()?.map { (it as ASN1Integer).value.toInt() }
	val algorithm get() = (tagMap[TagIndex.Algorithm.index] as? ASN1Integer)?.value?.toInt()
	val keySize get() = (tagMap[TagIndex.KeySize.index] as? ASN1Integer)?.value?.toInt()
	val digest get() = (tagMap[TagIndex.Digest.index] as? ASN1Set)?.objects?.toList()?.map { (it as ASN1Integer).value.toInt() }
	val padding get() = (tagMap[TagIndex.Padding.index] as? ASN1Set)?.objects?.toList()?.map { (it as ASN1Integer).value.toInt() }
	val ecCurve get() = (tagMap[TagIndex.EcCurve.index] as? ASN1Integer)?.value?.toInt()
	val rsaPublicExponent get() = (tagMap[TagIndex.RsaPublicExponent.index] as? ASN1Integer)?.value?.toLong()
	val mgfDigest get() = (tagMap[TagIndex.MgfDigest.index] as? ASN1Set)?.objects?.toList()?.map { (it as ASN1Integer).value.toInt() }
	val rollbackResistance get() = when (tagMap[TagIndex.RollbackResistance.index]) {
		is ASN1Null -> true
		null -> null
		else -> false
	}
	val earlyBootOnly get() = when (tagMap[TagIndex.EarlyBootOnly.index]) {
		is ASN1Null -> true
		null -> null
		else -> false
	}
	val activeDateTime get() = (tagMap[TagIndex.ActiveDateTime.index] as? ASN1Integer)?.value?.toLong()
	val originationExpireDateTime get() = (tagMap[TagIndex.OriginationExpireDateTime.index] as? ASN1Integer)?.value?.toLong()
	val usageExpireDateTime get() = (tagMap[TagIndex.UsageExpireDateTime.index] as? ASN1Integer)?.value?.toLong()
	val usageCountLimit get() = (tagMap[TagIndex.UsageCountLimit.index] as? ASN1Integer)?.value?.toLong()
	val noAuthRequired get() = when (tagMap[TagIndex.NoAuthRequired.index]) {
		is ASN1Null -> true
		null -> null
		else -> false
	}
	val userAuthType get() = (tagMap[TagIndex.UserAuthType.index] as? ASN1Integer)?.value?.toInt()
	val authTimeout get() = (tagMap[TagIndex.AuthTimeout.index] as? ASN1Integer)?.value?.toInt()
	val allowWhileOnBody get() = when (tagMap[TagIndex.AllowWhileOnBody.index]) {
		is ASN1Null -> true
		null -> null
		else -> false
	}
	val trustedUserPresenceRequired get() = when (tagMap[TagIndex.TrustedUserPresenceRequired.index]) {
		is ASN1Null -> true
		null -> null
		else -> false
	}
	val trustedConfirmationRequired get() = when (tagMap[TagIndex.TrustedConfirmationRequired.index]) {
		is ASN1Null -> true
		null -> null
		else -> false
	}
	val unlockedDeviceRequired get() = when (tagMap[TagIndex.UnlockedDeviceRequired.index]) {
		is ASN1Null -> true
		null -> null
		else -> false
	}
	val allApplications get() = when (tagMap[TagIndex.AllApplications.index]) {
		is ASN1Null -> true
		null -> null
		else -> false
	}
	val applicationId get() = (tagMap[TagIndex.ApplicationId.index] as? DEROctetString)?.octets?.let { String(it) }
	val creationDateTime get() = (tagMap[TagIndex.CreationDateTime.index] as? ASN1Integer)?.value?.toLong()
	val origin get() = (tagMap[TagIndex.Origin.index] as? ASN1Integer)?.value?.toInt()
	val rootOfTrust get() = (tagMap[TagIndex.RootOfTrust.index] as? ASN1Sequence)?.let { parseRootOfTrust(it) }
	val osVersion get() = (tagMap[TagIndex.OsVersion.index] as? ASN1Integer)?.value?.toInt()
	val osPatchLevel get() = (tagMap[TagIndex.OsPatchLevel.index] as? ASN1Integer)?.value?.toInt()
	val attestationApplicationId get() = (tagMap[TagIndex.AttestationApplicationId.index] as? DEROctetString)?.octets
	val attestationIdBrand get() = (tagMap[TagIndex.AttestationIdBrand.index] as? DEROctetString)?.octets?.let { String(it) }
	val attestationIdDevice get() = (tagMap[TagIndex.AttestationIdDevice.index] as? DEROctetString)?.octets?.let { String(it) }
	val attestationIdProduct get() = (tagMap[TagIndex.AttestationIdProduct.index] as? DEROctetString)?.octets?.let { String(it) }
	val attestationIdSerial get() = (tagMap[TagIndex.AttestationIdSerial.index] as? DEROctetString)?.octets?.let { String(it) }
	val attestationIdImei get() = (tagMap[TagIndex.AttestationIdImei.index] as? DEROctetString)?.octets?.let { String(it) }
	val attestationIdMeid get() = (tagMap[TagIndex.AttestationIdMeid.index] as? DEROctetString)?.octets?.let { String(it) }
	val attestationIdManufacturer get() = (tagMap[TagIndex.AttestationIdManufacturer.index] as? DEROctetString)?.octets?.let { String(it) }
	val attestationIdModel get() = (tagMap[TagIndex.AttestationIdModel.index] as? DEROctetString)?.octets?.let { String(it) }
	val vendorPatchLevel get() = (tagMap[TagIndex.VendorPatchLevel.index] as? ASN1Integer)?.value?.toInt()
	val bootPatchLevel get() = (tagMap[TagIndex.BootPatchLevel.index] as? ASN1Integer)?.value?.toInt()
	val deviceUniqueAttestation get() =
		when (tagMap[TagIndex.DeviceUniqueAttestation.index]) {
			is ASN1Null -> true
			null -> null
			else -> false
		}

	private fun parseRootOfTrust(sequence: ASN1Sequence): RootOfTrust {
		val iterator = sequence.objects

		val verifiedBootKey = String((iterator.nextElement() as DEROctetString).octets)
		val deviceLocked = (iterator.nextElement() as ASN1Boolean).isTrue
		val verifiedBootState = (iterator.nextElement() as ASN1Enumerated).value.toInt()

		var verifiedBootHash : String? = null
		if (iterator.hasMoreElements()) {
			verifiedBootHash = String((iterator.nextElement() as DEROctetString).octets)
		}

		return RootOfTrust(verifiedBootKey, deviceLocked, verifiedBootState, verifiedBootHash)
	}
}