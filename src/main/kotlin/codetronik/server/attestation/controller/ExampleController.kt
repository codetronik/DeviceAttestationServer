package codetronik.server.attestation.controller

import codetronik.server.attestation.service.MyService
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController

data class BaseReponse(
	val resultCode: Int
)

data class CertChain(
	val certChain : String
)

@RestController
class ExampleController(val myService : MyService) {
	@GetMapping("/getChallange")
	fun getChallange() : String {
		return myService.createChallange()
	}

	@PostMapping("/sendCertChain")
	fun sendCertChain(@RequestBody data: CertChain) : BaseReponse {
		if (!myService.sendCertChain(data.certChain)) {
			return BaseReponse(resultCode = -1)
		}
		return BaseReponse(resultCode = 0)
	}
}