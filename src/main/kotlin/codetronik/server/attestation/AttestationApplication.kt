package codetronik.server.attestation

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.cache.annotation.EnableCaching

@SpringBootApplication
@EnableCaching
class AttestationApplication

fun main(args: Array<String>) {
	runApplication<AttestationApplication>(*args)
}